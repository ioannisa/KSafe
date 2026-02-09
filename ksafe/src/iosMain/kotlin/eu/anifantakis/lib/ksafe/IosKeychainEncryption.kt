package eu.anifantakis.lib.ksafe

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.providers.cryptokit.CryptoKit
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.refTo
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.runBlocking
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSData
import platform.Foundation.create
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.errSecInteractionNotAllowed
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.Security.SecItemUpdate
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecReturnData
import platform.Security.kSecValueData
import platform.posix.memcpy
import kotlin.random.Random

/**
 * iOS implementation of [KSafeEncryption] using iOS Keychain Services and CryptoKit.
 *
 * This provides secure encryption with:
 * - Symmetric AES keys stored as Keychain generic-password items (protected by device passcode)
 * - Keys not included in iCloud/iTunes backups (`ThisDeviceOnly` accessibility)
 * - Access control: configurable via [KSafeConfig.requireUnlockedDevice]
 *   (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`)
 *
 * Note: These are software-backed symmetric keys stored in the Keychain, not Secure Enclave keys.
 * The Secure Enclave only supports asymmetric keys (EC P-256). The Keychain itself is encrypted
 * by the OS and protected by the device passcode, providing strong at-rest protection.
 *
 * @property config Configuration for encryption (key size)
 * @property serviceName The Keychain service name for key storage
 */
@PublishedApi
internal class IosKeychainEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val serviceName: String = SERVICE_NAME
) : KSafeEncryption {

    companion object {
        private const val SERVICE_NAME = "eu.anifantakis.ksafe"
    }

    // Key size in bytes (256 bits = 32 bytes, 128 bits = 16 bytes)
    private val keySizeBytes: Int = config.keySize / 8

    override fun encrypt(identifier: String, data: ByteArray): ByteArray {
        val keyBytes = getOrCreateKeychainKey(identifier)

        // Use runBlocking because the cryptography library uses suspend functions
        return runBlocking {
            val aesGcm = CryptographyProvider.CryptoKit.get(AES.GCM)
            val symmetricKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, keyBytes)
            val cipher = symmetricKey.cipher()
            cipher.encrypt(plaintext = data)
        }
    }

    override fun decrypt(identifier: String, data: ByteArray): ByteArray {
        // Key was created with its accessibility setting - just retrieve it
        val keyBytes = getExistingKeychainKey(identifier)

        return runBlocking {
            val aesGcm = CryptographyProvider.CryptoKit.get(AES.GCM)
            val symmetricKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, keyBytes)
            val cipher = symmetricKey.cipher()
            cipher.decrypt(ciphertext = data)
        }
    }

    override fun deleteKey(identifier: String) {
        deleteFromKeychain(identifier)
    }

    /**
     * Gets an existing encryption key from iOS Keychain (for decryption).
     * Does not create a new key - if the key doesn't exist, throws an exception.
     *
     * @param keyId The key identifier (will be used as the Keychain account)
     * @return The encryption key bytes
     * @throws IllegalStateException if the key doesn't exist or is inaccessible
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getExistingKeychainKey(keyId: String): ByteArray {
        memScoped {
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                null,
                null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
                CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(serviceName))
                CFDictionarySetValue(this, kSecAttrAccount, CFBridgingRetain(keyId))
                CFDictionarySetValue(this, kSecReturnData, kCFBooleanTrue)
                CFDictionarySetValue(this, kSecMatchLimit, kSecMatchLimitOne)
            }

            val resultRef = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, resultRef.ptr)
            CFRelease(query as CFTypeRef?)

            when (status) {
                errSecSuccess -> {
                    val data = CFBridgingRelease(resultRef.value) as NSData
                    return data.toByteArray()
                }
                platform.Security.errSecItemNotFound -> {
                    throw IllegalStateException("KSafe: No encryption key found for identifier: $keyId")
                }
                errSecInteractionNotAllowed -> {
                    throw IllegalStateException("KSafe: Cannot access Keychain - device is locked. Key exists but is inaccessible.")
                }
                else -> {
                    throw IllegalStateException("KSafe: Keychain error $status for key $keyId")
                }
            }
        }
    }

    /**
     * Gets or creates an encryption key from iOS Keychain.
     *
     * If the key exists in the Keychain, it is retrieved. Otherwise, a new
     * random key is generated and stored in the Keychain.
     *
     * @param keyId The key identifier (will be used as the Keychain account)
     * @return The encryption key bytes
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getOrCreateKeychainKey(keyId: String): ByteArray {
        // Try to retrieve existing key from Keychain
        memScoped {
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                null,
                null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
                CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(serviceName))
                CFDictionarySetValue(this, kSecAttrAccount, CFBridgingRetain(keyId))
                CFDictionarySetValue(this, kSecReturnData, kCFBooleanTrue)
                CFDictionarySetValue(this, kSecMatchLimit, kSecMatchLimitOne)
            }

            val resultRef = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, resultRef.ptr)
            CFRelease(query as CFTypeRef?)

            when (status) {
                errSecSuccess -> {
                    val data = CFBridgingRelease(resultRef.value) as NSData
                    return data.toByteArray()
                }
                // Item not found - will create new key below
                platform.Security.errSecItemNotFound -> {
                    // Continue to key generation
                }
                // Device is locked - key exists but cannot be accessed right now
                // Do NOT create a new key, throw error to avoid data loss
                errSecInteractionNotAllowed -> {
                    throw IllegalStateException("KSafe: Cannot access Keychain - device is locked. Key exists but is inaccessible.")
                }
                // Other errors - log and throw to avoid silent data loss
                else -> {
                    throw IllegalStateException("KSafe: Keychain error $status for key $keyId")
                }
            }
        }

        // Key doesn't exist, generate new one with configured size
        val newKey = ByteArray(keySizeBytes)
        Random.nextBytes(newKey)

        // Store in keychain
        storeInKeychain(keyId, newKey)

        return newKey
    }

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun storeInKeychain(keyId: String, keyData: ByteArray) {
        memScoped {
            val nsData = NSData.create(
                bytes = keyData.refTo(0).getPointer(this),
                length = keyData.size.toULong()
            )

            val addQuery = CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                null,
                null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
                CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(serviceName))
                CFDictionarySetValue(this, kSecAttrAccount, CFBridgingRetain(keyId))
                CFDictionarySetValue(this, kSecValueData, CFBridgingRetain(nsData))
                val accessibility = if (config.requireUnlockedDevice)
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                else
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                CFDictionarySetValue(this, kSecAttrAccessible, accessibility)
            }

            // First delete any existing item with the same key
            val deleteQuery = CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                null,
                null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
                CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(serviceName))
                CFDictionarySetValue(this, kSecAttrAccount, CFBridgingRetain(keyId))
            }
            SecItemDelete(deleteQuery)
            CFRelease(deleteQuery as CFTypeRef?)

            // Now add the new item
            val addStatus = SecItemAdd(addQuery, null)
            CFRelease(addQuery as CFTypeRef?)

            if (addStatus != errSecSuccess) {
                when (addStatus) {
                    errSecInteractionNotAllowed -> throw IllegalStateException(
                        "KSafe: Cannot store key in Keychain - device is locked."
                    )
                    else -> throw IllegalStateException(
                        "KSafe: Failed to store key in Keychain, status: $addStatus"
                    )
                }
            }
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    override fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) {
        memScoped {
            // Build query to find the existing Keychain item
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
                CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(serviceName))
                CFDictionarySetValue(this, kSecAttrAccount, CFBridgingRetain(identifier))
            }

            // Build update dictionary with the new accessibility attribute
            val update = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
            ).apply {
                val accessibility = if (requireUnlocked)
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                else
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                CFDictionarySetValue(this, kSecAttrAccessible, accessibility)
            }

            val updateStatus = SecItemUpdate(query, update)

            CFRelease(query as CFTypeRef?)
            CFRelease(update as CFTypeRef?)

            if (updateStatus != errSecSuccess && updateStatus != platform.Security.errSecItemNotFound) {
                when (updateStatus) {
                    errSecInteractionNotAllowed -> throw IllegalStateException(
                        "KSafe: Cannot update Keychain accessibility - device is locked."
                    )
                    else -> throw IllegalStateException(
                        "KSafe: Failed to update Keychain accessibility, status: $updateStatus"
                    )
                }
            }
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun deleteFromKeychain(keyId: String) {
        memScoped {
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                null,
                null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
                CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(serviceName))
                CFDictionarySetValue(this, kSecAttrAccount, CFBridgingRetain(keyId))
            }

            SecItemDelete(query)
            CFRelease(query as CFTypeRef?)
        }
    }

    /**
     * Extension function to convert NSData to ByteArray
     */
    @OptIn(ExperimentalForeignApi::class)
    private fun NSData.toByteArray(): ByteArray {
        return ByteArray(this.length.toInt()).apply {
            usePinned {
                memcpy(it.addressOf(0), this@toByteArray.bytes, this@toByteArray.length)
            }
        }
    }
}
