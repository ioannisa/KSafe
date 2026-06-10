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
import platform.Foundation.NSOSStatusErrorDomain
import platform.Foundation.NSRecursiveLock
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.create
import platform.Foundation.dataUsingEncoding
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateDecryptedData
import platform.Security.SecKeyCreateEncryptedData
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyRef
import platform.Security.errSecAuthFailed
import platform.Security.errSecInteractionNotAllowed
import platform.Security.errSecItemNotFound
import platform.Security.errSecNotAvailable
import platform.Security.errSecSuccess
import platform.Security.errSecUserCanceled
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
 * Apple-platform implementation of [KSafeEncryption] using Keychain Services and CryptoKit.
 *
 * Used by iOS, iPadOS and macOS targets. The Keychain APIs (`SecItemAdd`/`SecItemCopyMatching`/
 * `SecKey…`), Secure Enclave token attribute and CryptoKit AES-GCM are all available and
 * behave identically across these platforms; only the location of the Keychain database
 * differs (per-app on iOS, per-user on macOS).
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
 * for the key material. If the Secure Enclave is unavailable (e.g. on simulators, on
 * Intel Macs without a T2 chip, or older devices), the path falls back to regular
 * Keychain storage automatically.
 *
 * @property config Configuration for encryption (key size, default unlock policy).
 * @property serviceName The Keychain service name all items are scoped under.
 */
/**
 * The low-level generic-password Keychain operations the engine depends on, behind a seam
 * so tests can inject an in-memory fake. Real Keychain round-trips can't run in the
 * Kotlin/Native test runner (no entitlements → `errSecMissingEntitlement`), so this is the
 * only way to unit-test the engine's concurrency invariants (deep-review #8). Production uses
 * [AppleKeychainEncryption.RealKeychainStore], which calls `SecItem*`.
 */
internal interface AppleKeychainStore {
    /** Bytes stored at [account], or null if absent. Throws on locked/other Keychain errors. */
    fun readBytes(account: String): ByteArray?

    /** Replaces (delete-then-add) the item at [account]. Throws on failure. */
    fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean)

    /** Removes the item at [account]. No-op if absent; never throws. */
    fun delete(account: String)
}

@PublishedApi
internal class AppleKeychainEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val serviceName: String = SERVICE_NAME,
    /**
     * Test seam: an in-memory [AppleKeychainStore] for unit tests. Null in production, where
     * the engine uses [RealKeychainStore] (real `SecItem*` calls).
     */
    keychainStore: AppleKeychainStore? = null,
) : KSafeEncryption {

    /** Generic-password Keychain access — real `SecItem*` in production, a fake in tests. */
    private val keychain: AppleKeychainStore = keychainStore ?: RealKeychainStore()

    /** Production [AppleKeychainStore]: delegates to the engine's `SecItem*` helpers. */
    private inner class RealKeychainStore : AppleKeychainStore {
        override fun readBytes(account: String): ByteArray? = copyKeychainBytes(account)
        override fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean) =
            storeInKeychain(account, bytes, requireUnlocked)
        override fun delete(account: String) = deleteFromKeychain(account)
    }

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
         * OSStatus codes whose SE/unwrap failure is transient (NOT corruption),
         * so the SE key must be preserved and the error propagated rather than
         * triggering destructive regeneration. Deliberately conservative: every
         * plausibly-retryable code stays here, biasing away from the
         * data-destroying path (deep-review #31).
         */
        private val TRANSIENT_OSSTATUS: Set<Long> = setOf(
            errSecInteractionNotAllowed.toLong(), // -25308: device locked
            errSecNotAvailable.toLong(),          // -25291: keychain/securityd not ready
            errSecAuthFailed.toLong(),            // -25293: auth failed (retryable)
            errSecUserCanceled.toLong(),          // -128: user cancelled the auth prompt
        )

        private val OSSTATUS_TAG = Regex("""osstatus=(-?\d+)""")

        /**
         * True when an unwrap/SE error is transient (device locked, SE busy,
         * interaction needed) and should propagate rather than trigger
         * destructive cleanup.
         *
         * Primary signal is the locale-independent `[osstatus=<code>]` tag
         * [cfErrorDescription] embeds for OSStatus-domain CFErrors — so the
         * decision never depends on the device's localized error text
         * (deep-review #31). The English-substring check remains only as a
         * fallback for the hand-written ISE messages that already state the
         * condition in words.
         */
        internal fun isTransientUnwrapFailure(message: String?): Boolean {
            val msg = message ?: return false
            val code = OSSTATUS_TAG.find(msg)?.groupValues?.get(1)?.toLongOrNull()
            if (code != null && code in TRANSIENT_OSSTATUS) return true
            return msg.contains("device is locked", ignoreCase = true) ||
                msg.contains("interaction", ignoreCase = true)
        }

        /**
         * Builds the SE wrap/unwrap failure message. When [detail]'s OSStatus
         * code classifies as transient, the message is branded with a
         * "Keychain" marker — the wording `KSafeCore.isTransientDecryptFailure`
         * already recognizes — because the engine-side classifier above is only
         * consulted on the key-CREATION path. Without the brand, a transient SE
         * unwrap during DECRYPT reached the core as an unrecognized message and
         * was misclassified permanent: `getDirect` silently returned the
         * caller's default for a HARDWARE_ISOLATED secret and `getFlow` emitted
         * it, instead of rethrowing-for-retry / skipping the emission
         * (review R30 — the decrypt-path half of review #31).
         */
        internal fun seFailureMessage(op: String, detail: String): String {
            val transientBrand =
                if (isTransientUnwrapFailure(detail)) " [transient Keychain failure]" else ""
            return "KSafe: Failed to $op AES key with Secure Enclave: $detail$transientBrand"
        }
    }

    private val keySizeBytes: Int = config.keySize / 8

    /**
     * In-process cache of unwrapped raw AES key bytes, keyed by the user-facing
     * `keyId`. Without this every `encrypt`/`decrypt` triggers a fresh
     * `SecItemCopyMatching` IPC into `securityd` (and, for SE-wrapped keys, an
     * additional `SecKeyCreateDecryptedData` ECIES round-trip). Keychain bytes
     * for a given alias are immutable for the alias's lifetime, so a simple
     * `KSafeConcurrentMap` cache is sound: invalidated only via [deleteKey],
     * never via accessibility updates (which preserve the bytes). The cache is
     * not persisted — process restart re-populates lazily on first use.
     *
     * Brings the Apple engine in line with the per-alias `SecretKey` handle
     * caches the Android and JVM engines already had — Apple was the outlier.
     */
    private val keyBytesCache = KSafeConcurrentMap<ByteArray>()

    /**
     * Serializes the *key-resolution* critical section (cache-miss → look up / create →
     * store → cache). Android and JVM serialize this per alias via `synchronized(lockFor)`,
     * and `KSafeCore` explicitly relies on engines doing so ("DEFAULT writes serialise on the
     * master alias's lock") — Apple had no lock at all. Concurrent creators are routine: the
     * construction-time master-key prewarm races the first DEFAULT write batch, and that batch
     * encrypts up to 8 entries in parallel against the **same** master alias. Without this
     * lock two threads both read `errSecItemNotFound`, both generate a key, and the
     * delete-then-add `storeInKeychain` lets the second clobber the first — after the first
     * already produced ciphertext under its key — silently and permanently losing that data
     * (deep-review #8).
     *
     * A single engine-wide lock (not per-alias) is sufficient and simpler: it guards only key
     * *resolution* (the cache-hit fast path below stays lock-free), so per-value AES never
     * contends; distinct aliases only serialize during their one-time creation. Reentrant so
     * the nested SE/plain/store helpers can't self-deadlock.
     */
    private val keyResolutionLock = NSRecursiveLock()

    @OptIn(ExperimentalForeignApi::class)
    private inline fun <R> withKeyResolutionLock(block: () -> R): R =
        // autoreleasepool drains the ObjC autoreleases produced by the NSRecursiveLock
        // method bridging — Kotlin/Native worker threads (Dispatchers.Default) have no
        // ambient pool, so without this the lock/unlock calls leak on every encrypt
        // (the same class of leak as issue #22).
        autoreleasepool {
            keyResolutionLock.lock()
            try {
                block()
            } finally {
                keyResolutionLock.unlock()
            }
        }

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

    /**
     * Description out of a CFError. For OSStatus-domain errors it appends a
     * locale-independent `[osstatus=<code>]` tag so transient-vs-permanent
     * classification can key on the numeric code instead of the localized text
     * (deep-review #31): on a non-English device the localized description of
     * `errSecInteractionNotAllowed` contains neither "device is locked" nor
     * "interaction", which previously made a transient (locked-device / SE-busy)
     * unwrap failure look permanent and trigger destructive key regeneration.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun cfErrorDescription(errorRef: CFErrorRefVar): String {
        val cfError = errorRef.value ?: return "no error details"
        val nsError = CFBridgingRelease(cfError) as? platform.Foundation.NSError
            ?: return "unknown error"
        val desc = nsError.localizedDescription
        return if (nsError.domain == NSOSStatusErrorDomain) "$desc [osstatus=${nsError.code}]" else desc
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
        keychain.delete(seWrappedAccount(identifier))
        deleteSecureEnclaveKey(seTag(identifier))
        keychain.delete(identifier)
        keyBytesCache.remove(identifier)
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
                    throw IllegalStateException(seFailureMessage(op, cfErrorDescription(errorRef)))
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
    private fun getExistingKeychainKeyRaw(keyId: String): ByteArray? = keychain.readBytes(keyId)

    /**
     * Retrieves an existing encryption key for decryption. Tries the SE-wrapped
     * account first, falls back to the plain account. Throws if neither exists —
     * decrypt has no "create on miss" semantics.
     *
     * Hits the in-process [keyBytesCache] before any Keychain IPC; the cache
     * holds the unwrapped raw AES key, so SE-wrapped keys also avoid the
     * `SecKeyCreateDecryptedData` ECIES round-trip on cache hit.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getExistingKeychainKey(keyId: String): ByteArray {
        // Decrypt path is read-only — it never creates or overwrites a Keychain item, so it
        // does NOT take keyResolutionLock (that guards key *creation*; #8's clobber is a
        // create-vs-create race). Keeping this lock-free also avoids a per-decrypt lock/bridge
        // cost on the hot read path (and the background-thread autorelease leak that guards).
        // Concurrent decrypts of the same alias are safe: they read the same Keychain bytes and
        // converge on the thread-safe keyBytesCache (idempotent last-writer-wins).
        keyBytesCache[keyId]?.let { return it }

        val wrappedBytes = getExistingKeychainKeyRaw(seWrappedAccount(keyId))
        val bytes = if (wrappedBytes != null) {
            val sePrivateKey = getSecureEnclaveKey(seTag(keyId))
                ?: throw IllegalStateException("KSafe: SE key missing for wrapped AES key: $keyId")
            try {
                unwrapAesKey(sePrivateKey, wrappedBytes)
            } finally {
                CFRelease(sePrivateKey)
            }
        } else {
            getExistingKeychainKeyRaw(keyId)
                ?: throw IllegalStateException("KSafe: No encryption key found for identifier: $keyId")
        }
        keyBytesCache[keyId] = bytes
        return bytes
    }

    /**
     * Gets an encryption key, creating one if it doesn't exist. When
     * [hardwareIsolated] is true the key is protected by an SE EC key pair (ECIES
     * wrap); transient failures propagate, genuine SE-unavailable errors fall back
     * to plain storage.
     *
     * Cache-first: a populated [keyBytesCache] entry short-circuits the entire
     * SE/plain decision tree. The cached bytes are populated by the first
     * lookup-or-create and remain valid until [deleteKey].
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getOrCreateKeychainKey(
        keyId: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ): ByteArray {
        keyBytesCache[keyId]?.let { return it }

        return withKeyResolutionLock {
            // Re-check under the lock: a concurrent creator may have just populated the cache
            // (and the Keychain), in which case we must reuse its key, not mint a clobbering one.
            keyBytesCache[keyId]?.let { return@withKeyResolutionLock it }

            val bytes = if (hardwareIsolated) {
                try {
                    getOrCreateKeychainKeyWithSE(keyId, requireUnlockedDevice)
                } catch (e: IllegalStateException) {
                    val msg = e.message ?: ""
                    if (isTransientUnwrapFailure(msg) ||
                        msg.contains("Keychain error") ||
                        // A store failure is NOT "SE unavailable": don't silently fall back to a
                        // divergent plain key under the same identifier (deep-review #8 secondary).
                        msg.contains("Failed to store key in Keychain")
                    ) throw e
                    // SE genuinely unavailable (simulator, old device, no entitlements)
                    getOrCreateKeychainKeyPlain(keyId, requireUnlockedDevice)
                }
            } else {
                getOrCreateKeychainKeyPlain(keyId, requireUnlockedDevice)
            }
            keyBytesCache[keyId] = bytes
            bytes
        }
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
                    keychain.delete(seWrappedAccount(keyId))
                } finally {
                    CFRelease(sePrivateKey)
                }
            } else {
                // SE key truly not found — wrapped blob is unusable, clean up.
                keychain.delete(seWrappedAccount(keyId))
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
                keychain.store(seWrappedAccount(keyId), wrapped, resolvedRequireUnlockedDevice(requireUnlockedDevice))
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
        keychain.store(keyId, newKey, resolvedRequireUnlockedDevice(requireUnlockedDevice))
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
