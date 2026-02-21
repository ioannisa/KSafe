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
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSData
import platform.Foundation.NSNumber
import platform.Foundation.NSString
import platform.Foundation.create
import platform.Foundation.dataUsingEncoding
import platform.Foundation.NSUTF8StringEncoding
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateDecryptedData
import platform.Security.SecKeyCreateEncryptedData
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyRef
import platform.Security.errSecInteractionNotAllowed
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPrivate
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecAttrService
import platform.Security.kSecAttrTokenID
import platform.Security.kSecAttrTokenIDSecureEnclave
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecClassKey
import platform.Security.kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecPrivateKeyAttrs
import platform.Security.kSecReturnData
import platform.Security.kSecReturnRef
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
 * When [useSecureEnclave] is true, encryption keys are protected using **envelope encryption**:
 * an EC P-256 key pair is created in the Secure Enclave hardware, which wraps/unwraps the AES
 * symmetric key using ECIES. The AES key itself is stored encrypted in the Keychain. This provides
 * hardware-level protection for the key material. If the Secure Enclave is unavailable (e.g., on
 * simulators or older devices), it falls back to regular Keychain storage automatically.
 *
 * @property config Configuration for encryption (key size)
 * @property serviceName The Keychain service name for key storage
 * @property useSecureEnclave When true, protects encryption keys using the Secure Enclave via envelope encryption
 */
@PublishedApi
internal class IosKeychainEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val serviceName: String = SERVICE_NAME
) : KSafeEncryption {

    companion object {
        private const val SERVICE_NAME = "eu.anifantakis.ksafe"
        internal const val SE_KEY_TAG_PREFIX = "se."

        /**
         * Returns Keychain account lookup order for a given key id.
         *
         * Always checks SE-wrapped path first, then falls back to plain:
         * 1) SE-wrapped key account: `se.{keyId}`
         * 2) Legacy plain key account: `{keyId}`
         */
        internal fun keychainLookupOrder(keyId: String): List<String> {
            val wrapped = "$SE_KEY_TAG_PREFIX$keyId"
            return listOf(wrapped, keyId)
        }

        /**
         * Returns true when an unwrap error is likely transient and should be re-thrown
         * (to avoid destructive cleanup on recoverable conditions).
         */
        internal fun isTransientUnwrapFailure(message: String?): Boolean {
            val msg = message ?: return false
            return msg.contains("device is locked", ignoreCase = true) ||
                    msg.contains("interaction", ignoreCase = true)
        }
    }

    // Key size in bytes (256 bits = 32 bytes, 128 bits = 16 bytes)
    private val keySizeBytes: Int = config.keySize / 8

    override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean): ByteArray {
        val keyBytes = getOrCreateKeychainKey(identifier, hardwareIsolated)

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
        // Always attempt to delete SE artifacts regardless of useSecureEnclave flag.
        // This ensures orphan cleanup works even when the current instance has SE disabled.
        // SecItemDelete on nonexistent items is a harmless no-op (errSecItemNotFound).
        deleteFromKeychain(seWrappedAccount(identifier))
        deleteSecureEnclaveKey(seTag(identifier))
        // Always delete the plain key (handles legacy + non-SE case)
        deleteFromKeychain(identifier)
    }

    // ============ SECURE ENCLAVE NAMING HELPERS ============

    /** Application tag for the SE EC key pair. */
    private fun seTag(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    /** Keychain account for the SE-wrapped (ECIES-encrypted) AES key. */
    private fun seWrappedAccount(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    // ============ SECURE ENCLAVE KEY MANAGEMENT ============

    /**
     * Creates a new EC P-256 key pair in the Secure Enclave.
     *
     * @param tag The applicationTag used to identify the SE key
     * @return The SE private key reference
     * @throws IllegalStateException if SE key creation fails
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun createSecureEnclaveKey(tag: String): SecKeyRef {
        // Delete any existing SE key with this tag first to prevent duplicates.
        // SecKeyCreateRandomKey always creates a new key (even if the tag exists),
        // and duplicate keys cause SecItemCopyMatching to return the wrong one.
        deleteSecureEnclaveKey(tag)

        return memScoped {
            val tagData = (tag as NSString).dataUsingEncoding(NSUTF8StringEncoding)
                ?: throw IllegalStateException("KSafe: Failed to encode SE tag")

            val accessibility = if (config.requireUnlockedDevice)
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            else
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

            // Private key attributes
            val privateKeyAttrs = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
            ).apply {
                CFDictionarySetValue(this, kSecAttrIsPermanent, kCFBooleanTrue)
                CFDictionarySetValue(this, kSecAttrApplicationTag, CFBridgingRetain(tagData))
                CFDictionarySetValue(this, kSecAttrAccessible, accessibility)
            }

            // Key generation attributes
            val attributes = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
            ).apply {
                CFDictionarySetValue(this, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
                CFDictionarySetValue(this, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(int = 256)))
                CFDictionarySetValue(this, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
                CFDictionarySetValue(this, kSecPrivateKeyAttrs, privateKeyAttrs)
            }

            val keyErrorRef = alloc<CFErrorRefVar>()
            val privateKey = SecKeyCreateRandomKey(attributes, keyErrorRef.ptr)

            CFRelease(privateKeyAttrs as CFTypeRef?)
            CFRelease(attributes as CFTypeRef?)

            if (privateKey == null) {
                val cfError = keyErrorRef.value
                val errorDesc = if (cfError != null) {
                    val nsError = CFBridgingRelease(cfError) as? platform.Foundation.NSError
                    nsError?.localizedDescription ?: "unknown error"
                } else "no error details"
                throw IllegalStateException(
                    "KSafe: Failed to create Secure Enclave key: $errorDesc"
                )
            }
            privateKey
        }
    }

    /**
     * Retrieves an existing EC private key from the Secure Enclave.
     *
     * @param tag The applicationTag used to identify the SE key
     * @return The SE private key reference, or null if not found
     * @throws IllegalStateException on transient errors (device locked, missing entitlement)
     *   to prevent callers from mistaking a transient failure for "key not found"
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getSecureEnclaveKey(tag: String): SecKeyRef? {
        return memScoped {
            val tagData = (tag as NSString).dataUsingEncoding(NSUTF8StringEncoding)
                ?: return null

            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassKey)
                CFDictionarySetValue(this, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
                CFDictionarySetValue(this, kSecAttrApplicationTag, CFBridgingRetain(tagData))
                CFDictionarySetValue(this, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
                CFDictionarySetValue(this, kSecReturnRef, kCFBooleanTrue)
                CFDictionarySetValue(this, kSecMatchLimit, kSecMatchLimitOne)
            }

            val resultRef = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, resultRef.ptr)
            CFRelease(query as CFTypeRef?)

            when (status) {
                errSecSuccess -> {
                    if (resultRef.value != null) {
                        @Suppress("UNCHECKED_CAST")
                        resultRef.value as SecKeyRef
                    } else {
                        null
                    }
                }
                platform.Security.errSecItemNotFound -> null
                errSecInteractionNotAllowed -> throw IllegalStateException(
                    "KSafe: Cannot access Secure Enclave key - device is locked."
                )
                else -> throw IllegalStateException(
                    "KSafe: Keychain error $status retrieving SE key for tag $tag"
                )
            }
        }
    }

    /**
     * Wraps (encrypts) AES key bytes using the SE public key with ECIES.
     *
     * @param publicKey The SE public key
     * @param aesKeyBytes The raw AES key bytes to wrap
     * @return The ECIES-encrypted AES key bytes
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun wrapAesKey(publicKey: SecKeyRef, aesKeyBytes: ByteArray): ByteArray {
        return memScoped {
            val nsData = NSData.create(
                bytes = aesKeyBytes.refTo(0).getPointer(this),
                length = aesKeyBytes.size.toULong()
            )

            @Suppress("UNCHECKED_CAST")
            val cfData = CFBridgingRetain(nsData) as CFDataRef
            try {
                val errorRef = alloc<CFErrorRefVar>()
                val encrypted = SecKeyCreateEncryptedData(
                    publicKey,
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                    cfData,
                    errorRef.ptr
                )
                if (encrypted == null) {
                    val cfError = errorRef.value
                    val errorDesc = if (cfError != null) {
                        val nsError = CFBridgingRelease(cfError) as? platform.Foundation.NSError
                        nsError?.localizedDescription ?: "unknown error"
                    } else "no error details"
                    throw IllegalStateException(
                        "KSafe: Failed to wrap AES key with Secure Enclave: $errorDesc"
                    )
                }

                (CFBridgingRelease(encrypted) as NSData).toByteArray()
            } finally {
                CFRelease(cfData)
            }
        }
    }

    /**
     * Unwraps (decrypts) AES key bytes using the SE private key with ECIES.
     *
     * The error message includes the CFError description so callers can distinguish
     * transient failures (e.g., device locked) from permanent corruption.
     *
     * @param privateKey The SE private key
     * @param wrappedBytes The ECIES-encrypted AES key bytes
     * @return The raw AES key bytes
     * @throws IllegalStateException with error details if unwrap fails
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun unwrapAesKey(privateKey: SecKeyRef, wrappedBytes: ByteArray): ByteArray {
        return memScoped {
            val nsData = NSData.create(
                bytes = wrappedBytes.refTo(0).getPointer(this),
                length = wrappedBytes.size.toULong()
            )

            @Suppress("UNCHECKED_CAST")
            val cfData = CFBridgingRetain(nsData) as CFDataRef
            try {
                val errorRef = alloc<CFErrorRefVar>()
                val decrypted = SecKeyCreateDecryptedData(
                    privateKey,
                    kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                    cfData,
                    errorRef.ptr
                )
                if (decrypted == null) {
                    val errorDesc = errorRef.value?.let {
                        val desc = CFBridgingRelease(it) as? platform.Foundation.NSError
                        desc?.localizedDescription ?: "unknown error"
                    } ?: "unknown error"
                    throw IllegalStateException(
                        "KSafe: Failed to unwrap AES key with Secure Enclave: $errorDesc"
                    )
                }

                (CFBridgingRelease(decrypted) as NSData).toByteArray()
            } finally {
                CFRelease(cfData)
            }
        }
    }

    /**
     * Deletes an SE EC key pair from the Keychain by applicationTag.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun deleteSecureEnclaveKey(tag: String) {
        memScoped {
            val tagData = (tag as NSString).dataUsingEncoding(NSUTF8StringEncoding) ?: return

            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassKey)
                CFDictionarySetValue(this, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
                CFDictionarySetValue(this, kSecAttrApplicationTag, CFBridgingRetain(tagData))
            }

            SecItemDelete(query)
            CFRelease(query as CFTypeRef?)
        }
    }

    // ============ KEYCHAIN KEY RETRIEVAL (NULL-RETURNING) ============

    /**
     * Tries to retrieve an existing raw AES key from the Keychain.
     * Returns null if not found (does not throw on errSecItemNotFound).
     *
     * @param keyId The key identifier (Keychain account)
     * @return Raw AES key bytes, or null if not found
     * @throws IllegalStateException on device-locked or other Keychain errors
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getExistingKeychainKeyRaw(keyId: String): ByteArray? {
        return memScoped {
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
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
                    data.toByteArray()
                }
                platform.Security.errSecItemNotFound -> null
                errSecInteractionNotAllowed -> throw IllegalStateException(
                    "KSafe: Cannot access Keychain - device is locked. Key exists but is inaccessible."
                )
                else -> throw IllegalStateException(
                    "KSafe: Keychain error $status for key $keyId"
                )
            }
        }
    }

    // ============ SE-AWARE KEY RETRIEVAL / CREATION ============

    /**
     * Gets an existing encryption key from iOS Keychain (for decryption).
     * Does not create a new key - if the key doesn't exist, throws an exception.
     *
     * When [useSecureEnclave] is true, checks for an SE-wrapped key first,
     * then falls back to a legacy unwrapped key.
     *
     * @param keyId The key identifier (will be used as the Keychain account)
     * @return The encryption key bytes
     * @throws IllegalStateException if the key doesn't exist or is inaccessible
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getExistingKeychainKey(keyId: String): ByteArray {
        // Always check SE-wrapped path first regardless of hardwareIsolated flag.
        // This ensures decrypt works for ANY key, even if the current call doesn't
        // request hardware isolation (the key may have been created with it).
        val wrappedBytes = getExistingKeychainKeyRaw(seWrappedAccount(keyId))
        if (wrappedBytes != null) {
            val sePrivateKey = getSecureEnclaveKey(seTag(keyId))
                ?: throw IllegalStateException("KSafe: SE key missing for wrapped AES key: $keyId")
            try {
                return unwrapAesKey(sePrivateKey, wrappedBytes)
            } finally {
                CFRelease(sePrivateKey)
            }
        }

        // Plain key lookup (original behavior)
        return getExistingKeychainKeyPlain(keyId)
    }

    /**
     * Original getExistingKeychainKey logic — retrieves a plain (unwrapped) AES key.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getExistingKeychainKeyPlain(keyId: String): ByteArray {
        memScoped {
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
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
     * When [useSecureEnclave] is true, the AES key is wrapped by an SE EC key pair.
     * Falls back to plain Keychain storage if the Secure Enclave is unavailable.
     *
     * @param keyId The key identifier (will be used as the Keychain account)
     * @return The encryption key bytes
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getOrCreateKeychainKey(keyId: String, hardwareIsolated: Boolean = false): ByteArray {
        if (hardwareIsolated) {
            return try {
                getOrCreateKeychainKeyWithSE(keyId)
            } catch (e: IllegalStateException) {
                val msg = e.message ?: ""
                // Re-throw transient / access errors — these are NOT "SE unavailable"
                // and should not silently downgrade to plain Keychain storage.
                if (msg.contains("device is locked") ||
                    msg.contains("Keychain error") ||
                    msg.contains("interaction", ignoreCase = true)) {
                    throw e
                }
                // SE genuinely unavailable (simulator, old device, no entitlements) — fall back to plain
                getOrCreateKeychainKeyPlain(keyId)
            }
        }
        return getOrCreateKeychainKeyPlain(keyId)
    }

    /**
     * SE path: gets or creates an AES key wrapped by a Secure Enclave EC key.
     *
     * Lookup order:
     * 1. SE-wrapped key exists (`se.{keyId}`) → unwrap and return
     * 2. Legacy unwrapped key exists (`{keyId}`) → return as-is (pre-SE data)
     * 3. Neither → create new SE-wrapped key
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getOrCreateKeychainKeyWithSE(keyId: String): ByteArray {
        // 1. Check for existing SE-wrapped key
        val wrappedBytes = getExistingKeychainKeyRaw(seWrappedAccount(keyId))
        if (wrappedBytes != null) {
            val sePrivateKey = getSecureEnclaveKey(seTag(keyId))
            if (sePrivateKey != null) {
                try {
                    return unwrapAesKey(sePrivateKey, wrappedBytes)
                } catch (e: IllegalStateException) {
                    // Re-throw transient errors (device locked, interaction not allowed)
                    // to prevent destructive cleanup on a recoverable failure.
                    if (isTransientUnwrapFailure(e.message)) {
                        throw e
                    }
                    // Permanent failure (wrong key, corruption) — clean up and recreate.
                    deleteSecureEnclaveKey(seTag(keyId))
                    deleteFromKeychain(seWrappedAccount(keyId))
                } finally {
                    CFRelease(sePrivateKey)
                }
            } else {
                // SE key truly not found (errSecItemNotFound) — corrupt state, clean up.
                // getSecureEnclaveKey already throws on transient errors, so null
                // here means the key genuinely doesn't exist.
                deleteFromKeychain(seWrappedAccount(keyId))
            }
        }

        // 2. Check for legacy (unwrapped) key — pre-SE data, return as-is
        val legacyKey = getExistingKeychainKeyRaw(keyId)
        if (legacyKey != null) {
            return legacyKey
        }

        // 3. Create new SE-wrapped key
        val newAesKey = ByteArray(keySizeBytes)
        Random.nextBytes(newAesKey)

        // Create SE EC key pair (deletes any existing key with same tag first)
        val sePrivateKey = createSecureEnclaveKey(seTag(keyId))
        try {
            val sePublicKey = SecKeyCopyPublicKey(sePrivateKey)
                ?: throw IllegalStateException("KSafe: Failed to get SE public key")
            try {
                val wrapped = wrapAesKey(sePublicKey, newAesKey)
                storeInKeychain(seWrappedAccount(keyId), wrapped)
                return newAesKey
            } finally {
                CFRelease(sePublicKey)
            }
        } finally {
            CFRelease(sePrivateKey)
        }
    }

    /**
     * Original getOrCreateKeychainKey logic — plain (unwrapped) AES key storage.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getOrCreateKeychainKeyPlain(keyId: String): ByteArray {
        // Try to retrieve existing key from Keychain
        memScoped {
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
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

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    override fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) {
        // Update the plain key
        updateKeychainItemAccessibility(identifier, requireUnlocked)

        // Always update SE artifacts too (they may exist from a previous HARDWARE_ISOLATED write).
        // SecItemUpdate on nonexistent items returns errSecItemNotFound which we already handle.
        updateKeychainItemAccessibility(seWrappedAccount(identifier), requireUnlocked)
        updateSecureEnclaveKeyAccessibility(seTag(identifier), requireUnlocked)
    }

    /**
     * Updates the accessibility attribute on a Secure Enclave EC private key.
     *
     * SE keys are `kSecClassKey` items (not generic-password), so they need
     * a separate `SecItemUpdate` query targeting `kSecClassKey` with the
     * application tag.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun updateSecureEnclaveKeyAccessibility(tag: String, requireUnlocked: Boolean) {
        memScoped {
            val tagData = (tag as NSString).dataUsingEncoding(NSUTF8StringEncoding) ?: return

            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassKey)
                CFDictionarySetValue(this, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
                CFDictionarySetValue(this, kSecAttrApplicationTag, CFBridgingRetain(tagData))
            }

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

            // errSecItemNotFound is fine — SE key may not exist for this identifier
            if (updateStatus != errSecSuccess && updateStatus != platform.Security.errSecItemNotFound) {
                when (updateStatus) {
                    errSecInteractionNotAllowed -> throw IllegalStateException(
                        "KSafe: Cannot update SE key accessibility - device is locked."
                    )
                    else -> throw IllegalStateException(
                        "KSafe: Failed to update SE key accessibility, status: $updateStatus"
                    )
                }
            }
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun updateKeychainItemAccessibility(account: String, requireUnlocked: Boolean) {
        memScoped {
            // Build query to find the existing Keychain item
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
                CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(serviceName))
                CFDictionarySetValue(this, kSecAttrAccount, CFBridgingRetain(account))
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
