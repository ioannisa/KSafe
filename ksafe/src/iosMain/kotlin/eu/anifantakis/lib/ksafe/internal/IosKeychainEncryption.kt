package eu.anifantakis.lib.ksafe.internal

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.providers.cryptokit.CryptoKit
import eu.anifantakis.lib.ksafe.KSafeConfig
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.autoreleasepool
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.refTo
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.runBlocking
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFMutableDictionaryRef
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
import platform.Security.errSecItemNotFound
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

/**
 * iOS implementation of [KSafeEncryption] using iOS Keychain Services and CryptoKit.
 *
 * This provides secure encryption with:
 * - Symmetric AES keys stored as Keychain generic-password items (protected by device passcode)
 * - Keys not included in iCloud/iTunes backups (`ThisDeviceOnly` accessibility)
 * - Access control: configurable via [KSafeConfig.requireUnlockedDevice]
 *   (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`)
 *
 * When `hardwareIsolated = true` is requested, encryption keys are protected using
 * **envelope encryption**: an EC P-256 key pair is created in the Secure Enclave
 * hardware, which wraps/unwraps the AES symmetric key using ECIES. The AES key
 * itself is stored encrypted in the Keychain. This provides hardware-level protection
 * for the key material. If the Secure Enclave is unavailable (e.g. on simulators or
 * older devices), the path falls back to regular Keychain storage automatically.
 *
 * @property config Configuration for encryption (key size, default unlock policy).
 * @property serviceName The Keychain service name all items are scoped under.
 */
@PublishedApi
internal class IosKeychainEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val serviceName: String = SERVICE_NAME,
) : KSafeEncryption {

    companion object {
        private const val SERVICE_NAME = "eu.anifantakis.ksafe"
        internal const val SE_KEY_TAG_PREFIX = "se."

        /**
         * Returns Keychain account lookup order for a given key id: SE-wrapped first,
         * then legacy plain.
         */
        internal fun keychainLookupOrder(keyId: String): List<String> =
            listOf("$SE_KEY_TAG_PREFIX$keyId", keyId)

        /**
         * True when an unwrap error looks transient (device locked, interaction needed)
         * and should propagate rather than trigger destructive cleanup.
         */
        internal fun isTransientUnwrapFailure(message: String?): Boolean {
            val msg = message ?: return false
            return msg.contains("device is locked", ignoreCase = true) ||
                msg.contains("interaction", ignoreCase = true)
        }
    }

    private val keySizeBytes: Int = config.keySize / 8

    // ================================================================
    // Helper layer. Every Keychain operation in this file used to open
    // its own `CFDictionaryCreateMutable` block, manually set the same
    // three-or-four base attributes, and remember to `CFRelease` on every
    // exit path. These helpers hold that boilerplate once.
    // ================================================================

    private fun resolvedRequireUnlockedDevice(override: Boolean?): Boolean =
        override ?: config.requireUnlockedDevice

    /** Maps the unlock-policy boolean to the Keychain accessibility CFString. */
    @OptIn(ExperimentalForeignApi::class)
    private fun accessibleAttr(requireUnlocked: Boolean): CFTypeRef? =
        if (requireUnlocked) kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        else kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    /** Encodes an SE application-tag string as UTF-8 NSData. */
    @OptIn(BetaInteropApi::class)
    private fun tagAsNSData(tag: String): NSData? =
        (tag as NSString).dataUsingEncoding(NSUTF8StringEncoding)

    /** Localized description out of a CFError, with stable "no details" fallback. */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun cfErrorDescription(errorRef: CFErrorRefVar): String {
        val cfError = errorRef.value ?: return "no error details"
        val nsError = CFBridgingRelease(cfError) as? platform.Foundation.NSError
        return nsError?.localizedDescription ?: "unknown error"
    }

    /**
     * Builds a `kSecClassGenericPassword` query dictionary pre-populated with the
     * library's service name and the given account, runs [block] with it, and
     * releases the dictionary on every exit.
     *
     * [configure] lets the caller add class-specific attributes such as
     * `kSecReturnData`, `kSecValueData`, or `kSecAttrAccessible` before [block]
     * sees the dictionary.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private inline fun <R> usingPasswordQuery(
        account: String,
        configure: (CFMutableDictionaryRef?) -> Unit = {},
        block: (CFMutableDictionaryRef?) -> R,
    ): R {
        val dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        return try {
            CFDictionarySetValue(dict, kSecClass, kSecClassGenericPassword)
            CFDictionarySetValue(dict, kSecAttrService, CFBridgingRetain(serviceName))
            CFDictionarySetValue(dict, kSecAttrAccount, CFBridgingRetain(account))
            configure(dict)
            block(dict)
        } finally {
            CFRelease(dict as CFTypeRef?)
        }
    }

    /**
     * Builds a `kSecClassKey` query dictionary for an SE EC private key identified
     * by its application-tag data, runs [block] with it, and releases on every exit.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private inline fun <R> usingSeKeyQuery(
        tagData: NSData,
        configure: (CFMutableDictionaryRef?) -> Unit = {},
        block: (CFMutableDictionaryRef?) -> R,
    ): R {
        val dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        return try {
            CFDictionarySetValue(dict, kSecClass, kSecClassKey)
            CFDictionarySetValue(dict, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
            CFDictionarySetValue(dict, kSecAttrApplicationTag, CFBridgingRetain(tagData))
            configure(dict)
            block(dict)
        } finally {
            CFRelease(dict as CFTypeRef?)
        }
    }

    /**
     * Runs [block] inside a `kSecClassGenericPassword` `SecItemCopyMatching` for the
     * given account, returning the matched bytes or `null` on `errSecItemNotFound`
     * and throwing on transient / unexpected Keychain statuses.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun copyKeychainBytes(account: String): ByteArray? =
        autoreleasepool { memScoped {
            usingPasswordQuery(
                account = account,
                configure = { dict ->
                    CFDictionarySetValue(dict, kSecReturnData, kCFBooleanTrue)
                    CFDictionarySetValue(dict, kSecMatchLimit, kSecMatchLimitOne)
                },
            ) { query ->
                val resultRef = alloc<CFTypeRefVar>()
                when (val status = SecItemCopyMatching(query, resultRef.ptr)) {
                    errSecSuccess -> (CFBridgingRelease(resultRef.value) as NSData).toByteArray()
                    errSecItemNotFound -> null
                    errSecInteractionNotAllowed -> throw IllegalStateException(
                        "KSafe: Cannot access Keychain - device is locked. Key exists but is inaccessible."
                    )
                    else -> throw IllegalStateException(
                        "KSafe: Keychain error $status for account $account"
                    )
                }
            }
        } }

    // ================================================================
    // KSafeEncryption interface
    // ================================================================

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ): ByteArray {
        val keyBytes = getOrCreateKeychainKey(identifier, hardwareIsolated, requireUnlockedDevice)
        return runBlocking {
            val aesGcm = CryptographyProvider.CryptoKit.get(AES.GCM)
            val symmetricKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, keyBytes)
            symmetricKey.cipher().encrypt(plaintext = data)
        }
    }

    override fun decrypt(identifier: String, data: ByteArray): ByteArray {
        val keyBytes = getExistingKeychainKey(identifier)
        return runBlocking {
            val aesGcm = CryptographyProvider.CryptoKit.get(AES.GCM)
            val symmetricKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, keyBytes)
            symmetricKey.cipher().decrypt(ciphertext = data)
        }
    }

    override fun deleteKey(identifier: String) {
        // Delete SE artifacts unconditionally so orphan cleanup works even when the
        // current instance has SE disabled. SecItemDelete on nonexistent items is a
        // harmless no-op (errSecItemNotFound).
        deleteFromKeychain(seWrappedAccount(identifier))
        deleteSecureEnclaveKey(seTag(identifier))
        deleteFromKeychain(identifier)
    }

    // ================================================================
    // SE naming
    // ================================================================

    /** Application tag for the SE EC key pair. */
    private fun seTag(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    /** Keychain account for the SE-wrapped (ECIES-encrypted) AES key. */
    private fun seWrappedAccount(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    // ================================================================
    // SE key lifecycle
    // ================================================================

    /**
     * Creates a new EC P-256 key pair in the Secure Enclave with the given tag.
     * Any existing key under the same tag is deleted first — `SecKeyCreateRandomKey`
     * always creates a new key even if the tag already exists, which would leave
     * `SecItemCopyMatching` returning the wrong one.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun createSecureEnclaveKey(tag: String, requireUnlockedDevice: Boolean?): SecKeyRef {
        deleteSecureEnclaveKey(tag)
        return autoreleasepool { memScoped {
            val tagData = tagAsNSData(tag)
                ?: throw IllegalStateException("KSafe: Failed to encode SE tag")
            val accessibility = accessibleAttr(resolvedRequireUnlockedDevice(requireUnlockedDevice))

            val privateKeyAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
                CFDictionarySetValue(this, kSecAttrIsPermanent, kCFBooleanTrue)
                CFDictionarySetValue(this, kSecAttrApplicationTag, CFBridgingRetain(tagData))
                CFDictionarySetValue(this, kSecAttrAccessible, accessibility)
            }
            val attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
                CFDictionarySetValue(this, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
                CFDictionarySetValue(this, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(int = 256)))
                CFDictionarySetValue(this, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
                CFDictionarySetValue(this, kSecPrivateKeyAttrs, privateKeyAttrs)
            }

            val keyErrorRef = alloc<CFErrorRefVar>()
            val privateKey = SecKeyCreateRandomKey(attributes, keyErrorRef.ptr)
            CFRelease(privateKeyAttrs as CFTypeRef?)
            CFRelease(attributes as CFTypeRef?)

            privateKey ?: throw IllegalStateException(
                "KSafe: Failed to create Secure Enclave key: ${cfErrorDescription(keyErrorRef)}"
            )
        } }
    }

    /**
     * Retrieves an existing EC private key from the Secure Enclave, or `null` if not
     * found. Throws `IllegalStateException` on transient errors (locked device,
     * missing entitlement) so callers don't mistake those for "key not found".
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getSecureEnclaveKey(tag: String): SecKeyRef? =
        autoreleasepool { memScoped {
            val tagData = tagAsNSData(tag) ?: return@autoreleasepool null
            usingSeKeyQuery(
                tagData = tagData,
                configure = { dict ->
                    CFDictionarySetValue(dict, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
                    CFDictionarySetValue(dict, kSecReturnRef, kCFBooleanTrue)
                    CFDictionarySetValue(dict, kSecMatchLimit, kSecMatchLimitOne)
                },
            ) { query ->
                val resultRef = alloc<CFTypeRefVar>()
                when (val status = SecItemCopyMatching(query, resultRef.ptr)) {
                    errSecSuccess -> resultRef.value?.let {
                        @Suppress("UNCHECKED_CAST") it as SecKeyRef
                    }
                    errSecItemNotFound -> null
                    errSecInteractionNotAllowed -> throw IllegalStateException(
                        "KSafe: Cannot access Secure Enclave key - device is locked."
                    )
                    else -> throw IllegalStateException(
                        "KSafe: Keychain error $status retrieving SE key for tag $tag"
                    )
                }
            }
        } }

    /** Wraps (ECIES-encrypts) raw AES key bytes using an SE public key. */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun wrapAesKey(publicKey: SecKeyRef, aesKeyBytes: ByteArray): ByteArray =
        cryptWithSeKey(publicKey, aesKeyBytes, wrap = true)

    /**
     * Unwraps (ECIES-decrypts) AES key bytes using an SE private key. The error
     * message preserves the CFError description so the caller can distinguish
     * transient failures (device locked) from permanent corruption.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun unwrapAesKey(privateKey: SecKeyRef, wrappedBytes: ByteArray): ByteArray =
        cryptWithSeKey(privateKey, wrappedBytes, wrap = false)

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun cryptWithSeKey(key: SecKeyRef, input: ByteArray, wrap: Boolean): ByteArray =
        memScoped {
            val nsData = NSData.create(
                bytes = input.refTo(0).getPointer(this),
                length = input.size.toULong(),
            )
            @Suppress("UNCHECKED_CAST")
            val cfData = CFBridgingRetain(nsData) as CFDataRef
            try {
                val errorRef = alloc<CFErrorRefVar>()
                val algo = kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM
                val result = if (wrap) SecKeyCreateEncryptedData(key, algo, cfData, errorRef.ptr)
                             else SecKeyCreateDecryptedData(key, algo, cfData, errorRef.ptr)
                if (result == null) {
                    val op = if (wrap) "wrap" else "unwrap"
                    throw IllegalStateException(
                        "KSafe: Failed to $op AES key with Secure Enclave: ${cfErrorDescription(errorRef)}"
                    )
                }
                (CFBridgingRelease(result) as NSData).toByteArray()
            } finally {
                CFRelease(cfData)
            }
        }

    /** Deletes an SE EC key pair from the Keychain by applicationTag. */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun deleteSecureEnclaveKey(tag: String) {
        autoreleasepool { memScoped {
            val tagData = tagAsNSData(tag) ?: return@autoreleasepool
            usingSeKeyQuery(tagData) { query -> SecItemDelete(query) }
        } }
    }

    // ================================================================
    // Keychain CRUD for AES keys
    // ================================================================

    /**
     * Tries to retrieve an existing raw AES key for the given Keychain account.
     * Returns `null` on `errSecItemNotFound`. Throws on device-locked or other
     * Keychain errors so callers don't silently overwrite accessible-but-locked
     * material.
     */
    private fun getExistingKeychainKeyRaw(keyId: String): ByteArray? = copyKeychainBytes(keyId)

    /**
     * Retrieves an existing encryption key for decryption. Tries the SE-wrapped
     * account first, falls back to the plain account. Throws if neither exists —
     * decrypt has no "create on miss" semantics.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getExistingKeychainKey(keyId: String): ByteArray {
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
        return getExistingKeychainKeyRaw(keyId)
            ?: throw IllegalStateException("KSafe: No encryption key found for identifier: $keyId")
    }

    /**
     * Gets an encryption key, creating one if it doesn't exist. When
     * [hardwareIsolated] is true the key is protected by an SE EC key pair (ECIES
     * wrap); transient failures propagate, genuine SE-unavailable errors fall back
     * to plain storage.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getOrCreateKeychainKey(
        keyId: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ): ByteArray {
        if (hardwareIsolated) {
            return try {
                getOrCreateKeychainKeyWithSE(keyId, requireUnlockedDevice)
            } catch (e: IllegalStateException) {
                val msg = e.message ?: ""
                if (msg.contains("device is locked") ||
                    msg.contains("Keychain error") ||
                    msg.contains("interaction", ignoreCase = true)
                ) throw e
                // SE genuinely unavailable (simulator, old device, no entitlements)
                getOrCreateKeychainKeyPlain(keyId, requireUnlockedDevice)
            }
        }
        return getOrCreateKeychainKeyPlain(keyId, requireUnlockedDevice)
    }

    /**
     * SE path. Lookup order:
     *   1. SE-wrapped key exists (`se.{keyId}`) → unwrap and return.
     *   2. Legacy unwrapped key exists (`{keyId}`) → return as-is (pre-SE data).
     *   3. Neither → create a new SE-wrapped key.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getOrCreateKeychainKeyWithSE(keyId: String, requireUnlockedDevice: Boolean?): ByteArray {
        val wrappedBytes = getExistingKeychainKeyRaw(seWrappedAccount(keyId))
        if (wrappedBytes != null) {
            val sePrivateKey = getSecureEnclaveKey(seTag(keyId))
            if (sePrivateKey != null) {
                try {
                    return unwrapAesKey(sePrivateKey, wrappedBytes)
                } catch (e: IllegalStateException) {
                    if (isTransientUnwrapFailure(e.message)) throw e
                    // Permanent failure → clean up and recreate below.
                    deleteSecureEnclaveKey(seTag(keyId))
                    deleteFromKeychain(seWrappedAccount(keyId))
                } finally {
                    CFRelease(sePrivateKey)
                }
            } else {
                // SE key truly not found — wrapped blob is unusable, clean up.
                deleteFromKeychain(seWrappedAccount(keyId))
            }
        }

        // Legacy pre-SE plain key — honour it.
        getExistingKeychainKeyRaw(keyId)?.let { return it }

        // Create a fresh SE-wrapped key.
        val newAesKey = secureRandomBytes(keySizeBytes)
        val sePrivateKey = createSecureEnclaveKey(seTag(keyId), requireUnlockedDevice)
        try {
            val sePublicKey = SecKeyCopyPublicKey(sePrivateKey)
                ?: throw IllegalStateException("KSafe: Failed to get SE public key")
            try {
                val wrapped = wrapAesKey(sePublicKey, newAesKey)
                storeInKeychain(seWrappedAccount(keyId), wrapped, requireUnlockedDevice)
                return newAesKey
            } finally {
                CFRelease(sePublicKey)
            }
        } finally {
            CFRelease(sePrivateKey)
        }
    }

    /** Plain path — get or create an unwrapped AES key stored directly in the Keychain. */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getOrCreateKeychainKeyPlain(keyId: String, requireUnlockedDevice: Boolean?): ByteArray {
        getExistingKeychainKeyRaw(keyId)?.let { return it }
        val newKey = secureRandomBytes(keySizeBytes)
        storeInKeychain(keyId, newKey, requireUnlockedDevice)
        return newKey
    }

    /**
     * Adds a generic-password item carrying [keyData] under [keyId]. Any existing
     * item at the same account is deleted first so the `SecItemAdd` can't
     * duplicate-collision.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun storeInKeychain(keyId: String, keyData: ByteArray, requireUnlockedDevice: Boolean?) {
        autoreleasepool { memScoped {
            val nsData = NSData.create(
                bytes = keyData.refTo(0).getPointer(this),
                length = keyData.size.toULong(),
            )

            // Delete any pre-existing item at this account.
            usingPasswordQuery(keyId) { deleteQuery -> SecItemDelete(deleteQuery) }

            val addStatus = usingPasswordQuery(
                account = keyId,
                configure = { dict ->
                    CFDictionarySetValue(dict, kSecValueData, CFBridgingRetain(nsData))
                    CFDictionarySetValue(
                        dict,
                        kSecAttrAccessible,
                        accessibleAttr(resolvedRequireUnlockedDevice(requireUnlockedDevice)),
                    )
                },
            ) { addQuery -> SecItemAdd(addQuery, null) }

            if (addStatus != errSecSuccess) when (addStatus) {
                errSecInteractionNotAllowed -> throw IllegalStateException(
                    "KSafe: Cannot store key in Keychain - device is locked."
                )
                else -> throw IllegalStateException(
                    "KSafe: Failed to store key in Keychain, status: $addStatus"
                )
            }
        } }
    }

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    override fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) {
        updateKeychainItemAccessibility(identifier, requireUnlocked)
        updateKeychainItemAccessibility(seWrappedAccount(identifier), requireUnlocked)
        updateSecureEnclaveKeyAccessibility(seTag(identifier), requireUnlocked)
    }

    /**
     * Updates the accessibility attribute on a Secure-Enclave-held EC private key.
     * SE keys are `kSecClassKey` items, not generic-password, so they need their own
     * `SecItemUpdate` query.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun updateSecureEnclaveKeyAccessibility(tag: String, requireUnlocked: Boolean) {
        autoreleasepool { memScoped {
            val tagData = tagAsNSData(tag) ?: return@autoreleasepool
            val status = usingSeKeyQuery(tagData) { query ->
                runItemUpdate(query, requireUnlocked)
            }
            handleAccessibilityUpdateStatus(status, "SE key")
        } }
    }

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun updateKeychainItemAccessibility(account: String, requireUnlocked: Boolean) {
        autoreleasepool { memScoped {
            val status = usingPasswordQuery(account) { query ->
                runItemUpdate(query, requireUnlocked)
            }
            handleAccessibilityUpdateStatus(status, "Keychain")
        } }
    }

    /**
     * Runs `SecItemUpdate` with a one-attribute `kSecAttrAccessible` payload and
     * releases the update dictionary.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun runItemUpdate(query: CFMutableDictionaryRef?, requireUnlocked: Boolean): Int {
        val update = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        return try {
            CFDictionarySetValue(update, kSecAttrAccessible, accessibleAttr(requireUnlocked))
            SecItemUpdate(query, update)
        } finally {
            CFRelease(update as CFTypeRef?)
        }
    }

    private fun handleAccessibilityUpdateStatus(status: Int, what: String) {
        if (status == errSecSuccess || status == errSecItemNotFound) return
        when (status) {
            errSecInteractionNotAllowed -> throw IllegalStateException(
                "KSafe: Cannot update $what accessibility - device is locked."
            )
            else -> throw IllegalStateException(
                "KSafe: Failed to update $what accessibility, status: $status"
            )
        }
    }

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun deleteFromKeychain(keyId: String) {
        autoreleasepool { memScoped {
            usingPasswordQuery(keyId) { query -> SecItemDelete(query) }
            Unit
        } }
    }

    /** Converts NSData to a Kotlin ByteArray by pinned memcpy. */
    @OptIn(ExperimentalForeignApi::class)
    private fun NSData.toByteArray(): ByteArray =
        ByteArray(this.length.toInt()).apply {
            usePinned {
                memcpy(it.addressOf(0), this@toByteArray.bytes, this@toByteArray.length)
            }
        }
}
