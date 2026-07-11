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
 * Low-level generic-password Keychain operations behind a seam so tests can inject an
 * in-memory fake — real round-trips can't run in the Kotlin/Native test runner (no
 * entitlements). Production uses [AppleKeychainEncryption.RealKeychainStore].
 */
internal interface AppleKeychainStore {
    /** Bytes stored at [account], or null if absent. Throws on locked/other Keychain errors. */
    fun readBytes(account: String): ByteArray?

    /** Replaces (delete-then-add) the item at [account]. Throws on failure. */
    fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean)

    /** Removes the item at [account]. No-op if absent; never throws. */
    fun delete(account: String)
}

/**
 * Whether [AppleKeychainEncryption.updateKeyAccessibility] must run its `SecItemUpdate`
 * IPC: only when [target] differs from the policy last applied for this key-id this
 * process ([lastApplied]; `null` = not yet applied). Pure, so it's unit-testable.
 */
internal fun accessibilityUpdateNeeded(lastApplied: Boolean?, target: Boolean): Boolean =
    lastApplied != target

/**
 * Apple-platform [KSafeEncryption] over Keychain Services + CryptoKit, shared by iOS,
 * iPadOS and macOS (only the Keychain database location differs — per-app on iOS,
 * per-user on macOS).
 *
 * AES keys are stored as `ThisDeviceOnly` generic-password items (never backed up).
 * With `hardwareIsolated = true` the AES key is envelope-encrypted: an EC P-256 key in
 * the Secure Enclave wraps it via ECIES and only the wrapped key is stored; if the SE is
 * unavailable (simulators, Intel Macs, older devices) the path falls back to plain storage.
 *
 * On the iOS Simulator only, an entitlement-blocked Keychain (`errSecMissingEntitlement`,
 * -34018 — no signing team / Keychain Sharing capability) additionally falls back to a
 * sandbox file key store instead of failing every encrypted write; see
 * [SimulatorFallbackKeyStore]. Real devices never take that path.
 */
@PublishedApi
internal class AppleKeychainEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val serviceName: String = SERVICE_NAME,
    /** Test seam: in-memory [AppleKeychainStore] for unit tests; null in production. */
    keychainStore: AppleKeychainStore? = null,
    /**
     * Simulator-only escape hatch for an entitlement-blocked Keychain (see
     * [SimulatorFallbackKeyStore]). Defaults to the sandbox file store on the iOS
     * Simulator and to null (disabled) everywhere else. Not auto-enabled when
     * [keychainStore] is a test fake; tests inject their own.
     */
    private val simulatorFallback: SimulatorFallbackKeyStore? =
        if (keychainStore == null && SecurityChecker.isEmulator()) {
            FileSimulatorFallbackKeyStore(serviceName)
        } else {
            null
        },
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
         * `errSecMissingEntitlement`: the process has no Keychain entitlement — the
         * status an unsigned/unentitled Simulator build gets from every Keychain call.
         * Local constant; the Kotlin platform libs don't re-export this symbol.
         */
        internal const val ERR_SEC_MISSING_ENTITLEMENT = -34018

        /**
         * True when [message] carries the missing-entitlement OSStatus. Every engine
         * throw site embeds the raw numeric status, so the substring match is exact
         * and locale-independent.
         */
        internal fun isMissingEntitlementFailure(message: String?): Boolean =
            message?.contains(ERR_SEC_MISSING_ENTITLEMENT.toString()) == true

        /** Actionable suffix for -34018 errors; empty for every other status. */
        internal fun entitlementHint(status: Int): String =
            if (status == ERR_SEC_MISSING_ENTITLEMENT) {
                " (errSecMissingEntitlement: the process has no Keychain entitlement — " +
                    "select a signing team and/or add the Keychain Sharing capability in " +
                    "Xcode; on the iOS Simulator also try Device > Erase All Content and Settings)"
            } else {
                ""
            }

        /**
         * Returns Keychain account lookup order for a given key id: SE-wrapped first,
         * then legacy plain.
         */
        internal fun keychainLookupOrder(keyId: String): List<String> =
            listOf("$SE_KEY_TAG_PREFIX$keyId", keyId)

        /**
         * OSStatus codes whose SE/unwrap failure is transient (NOT corruption): the SE key
         * must be preserved and the error propagated rather than regenerated. Conservative
         * on purpose — every plausibly-retryable code stays here.
         */
        private val TRANSIENT_OSSTATUS: Set<Long> = setOf(
            errSecInteractionNotAllowed.toLong(), // -25308: device locked
            errSecNotAvailable.toLong(),          // -25291: keychain/securityd not ready
            errSecAuthFailed.toLong(),            // -25293: auth failed (retryable)
            errSecUserCanceled.toLong(),          // -128: user cancelled the auth prompt
        )

        private val OSSTATUS_TAG = Regex("""osstatus=(-?\d+)""")

        /**
         * True when an unwrap/SE error is transient (device locked, SE busy) and should
         * propagate rather than trigger destructive cleanup. Keys on the locale-independent
         * `[osstatus=<code>]` tag [cfErrorDescription] embeds; the English-substring check
         * is only a fallback for hand-written messages carrying no tag.
         */
        internal fun isTransientUnwrapFailure(message: String?): Boolean {
            val msg = message ?: return false
            val code = OSSTATUS_TAG.find(msg)?.groupValues?.get(1)?.toLongOrNull()
            if (code != null && code in TRANSIENT_OSSTATUS) return true
            return msg.contains("device is locked", ignoreCase = true) ||
                msg.contains("interaction", ignoreCase = true)
        }

        /**
         * Builds the SE wrap/unwrap failure message. A transient [detail] gets the
         * " [transient Keychain failure]" marker that `KSafeCore.isTransientDecryptFailure`
         * matches on the DECRYPT path — without it a transient SE unwrap would be
         * misclassified permanent and `getDirect` would silently return the caller's default.
         */
        internal fun seFailureMessage(op: String, detail: String): String {
            val transientBrand =
                if (isTransientUnwrapFailure(detail)) " [transient Keychain failure]" else ""
            return "KSafe: Failed to $op AES key with Secure Enclave: $detail$transientBrand"
        }
    }

    private val keySizeBytes: Int = config.keySize / 8

    /**
     * In-process cache of unwrapped raw AES key bytes by `keyId`, sparing every
     * encrypt/decrypt a `SecItemCopyMatching` IPC (and, for SE keys, an ECIES round-trip).
     * Keychain bytes are immutable for an alias's lifetime, so this is invalidated only via
     * [deleteKey], never by accessibility updates (which preserve the bytes).
     */
    private val keyBytesCache = KSafeConcurrentMap<ByteArray>()

    /**
     * Last `requireUnlocked` accessibility applied per key-id this process, letting
     * [updateKeyAccessibility] skip its three `SecItemUpdate` IPC round-trips when the policy
     * is unchanged (the common case). Set only after all three succeed, so a partial failure
     * retries on the next write. Invalidated by [deleteKey].
     */
    private val lastAppliedAccessibility = KSafeConcurrentMap<Boolean>()

    /**
     * Aliases served from [simulatorFallback] this process. Lets [encrypt] skip the
     * accessibility `SecItemUpdate` IPC for fallback keys (the Keychain would reject it
     * with -34018 on every write) and feeds the `protectionInfo` degrade report.
     */
    private val fallbackServedAliases = KSafeConcurrentMap<Boolean>()
    private val fallbackActivated = KSafeAtomicFlag(false)
    private val fallbackWarned = KSafeAtomicFlag(false)

    /** True once any key op was served from the Simulator fallback store. */
    internal fun isSimulatorFallbackActive(): Boolean = fallbackActivated.get()

    /** Records (and, once per process, warns about) a fallback-served alias. */
    private fun fallbackKeyServed(keyId: String) {
        fallbackServedAliases[keyId] = true
        fallbackActivated.set(true)
        if (fallbackWarned.compareAndSet(false, true)) {
            println(
                "KSafe WARNING: the Keychain rejected this process with errSecMissingEntitlement " +
                    "(-34018), so encryption keys are held in a sandbox file store instead " +
                    "(iOS Simulator only; real devices never use this fallback). This usually " +
                    "means the app has no signing team or Keychain Sharing capability — fix " +
                    "that to test real Keychain behavior. See KSafe.protectionInfo."
            )
        }
    }

    /**
     * Serializes the key-resolution critical section (cache-miss → look up / create → store →
     * cache). Without it two threads both read `errSecItemNotFound`, both generate a key, and
     * the delete-then-add `storeInKeychain` lets the second clobber the first — after the
     * first already produced ciphertext under its key — permanently losing that data. One
     * engine-wide lock suffices (the cache-hit fast path stays lock-free); reentrant so the
     * nested SE/plain/store helpers can't self-deadlock.
     */
    private val keyResolutionLock = NSRecursiveLock()

    @OptIn(ExperimentalForeignApi::class)
    private inline fun <R> withKeyResolutionLock(block: () -> R): R =
        // autoreleasepool drains the ObjC autoreleases from NSRecursiveLock bridging —
        // Kotlin/Native worker threads have no ambient pool, so lock/unlock would else leak.
        autoreleasepool {
            keyResolutionLock.lock()
            try {
                block()
            } finally {
                keyResolutionLock.unlock()
            }
        }

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
     * Description out of a CFError. For OSStatus-domain errors it appends a locale-independent
     * `[osstatus=<code>]` tag so transient-vs-permanent classification keys on the numeric
     * code, not the localized text (which on a non-English device would make a transient
     * locked-device failure look permanent and trigger destructive key regeneration).
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
     * Builds a `kSecClassGenericPassword` query for [account] under the library's service
     * name, lets [configure] add attributes, runs [block] with it, and releases on every exit.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private inline fun <R> usingPasswordQuery(
        account: String,
        configure: (CFMutableDictionaryRef?) -> Unit = {},
        block: (CFMutableDictionaryRef?) -> R,
    ): R {
        val dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        // The dict's null value-callbacks mean it does NOT retain its values: hold each
        // CFBridgingRetain +1 across [block] (alive during the SecItem* call), then release,
        // or every value leaks one pair per call.
        val serviceRef = CFBridgingRetain(serviceName)
        val accountRef = CFBridgingRetain(account)
        return try {
            CFDictionarySetValue(dict, kSecClass, kSecClassGenericPassword)
            CFDictionarySetValue(dict, kSecAttrService, serviceRef)
            CFDictionarySetValue(dict, kSecAttrAccount, accountRef)
            configure(dict)
            block(dict)
        } finally {
            CFRelease(dict as CFTypeRef?)
            CFRelease(serviceRef)
            CFRelease(accountRef)
        }
    }

    /** Builds a `kSecClassKey` query for the SE EC key with [tagData], runs [block], releases. */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private inline fun <R> usingSeKeyQuery(
        tagData: NSData,
        configure: (CFMutableDictionaryRef?) -> Unit = {},
        block: (CFMutableDictionaryRef?) -> R,
    ): R {
        val dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        // null value-callbacks → the dict does not retain [tagData]; hold the bridged +1
        // across [block], then release, or it leaks every call.
        val tagRef = CFBridgingRetain(tagData)
        return try {
            CFDictionarySetValue(dict, kSecClass, kSecClassKey)
            CFDictionarySetValue(dict, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
            CFDictionarySetValue(dict, kSecAttrApplicationTag, tagRef)
            configure(dict)
            block(dict)
        } finally {
            CFRelease(dict as CFTypeRef?)
            CFRelease(tagRef)
        }
    }

    /**
     * The bytes at [account] via `SecItemCopyMatching`, `null` on `errSecItemNotFound`,
     * throwing on transient / unexpected Keychain statuses.
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
                        "KSafe: Keychain error $status for account $account${entitlementHint(status)}"
                    )
                }
            }
        } }

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ): ByteArray {
        val keyBytes = getOrCreateKeychainKey(identifier, hardwareIsolated, requireUnlockedDevice)
        // HARDWARE_ISOLATED entries reuse ONE alias regardless of policy, so tightening
        // requireUnlockedDevice on an existing key must re-assert kSecAttrAccessible or the
        // item keeps its looser accessibility (DEFAULT entries encode policy in the alias, so
        // they need none). Best-effort: a transient SecItemUpdate failure must not drop an
        // otherwise-successful encrypt — the OS keeps enforcing the current policy and the
        // next write retries the tightening. Skipped for Simulator-fallback keys: they have
        // no Keychain item to update and the IPC would just re-fail with -34018 every write.
        if (hardwareIsolated && fallbackServedAliases[identifier] != true) {
            runCatching { updateKeyAccessibility(identifier, resolvedRequireUnlockedDevice(requireUnlockedDevice)) }
        }
        return runBlocking {
            val aesGcm = CryptographyProvider.CryptoKit.get(AES.GCM)
            val symmetricKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, keyBytes)
            symmetricKey.cipher().encrypt(plaintext = data)
        }
    }

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
        val keyBytes = getExistingKeychainKey(identifier, requireUnlockedDevice)
        return runBlocking {
            val aesGcm = CryptographyProvider.CryptoKit.get(AES.GCM)
            val symmetricKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, keyBytes)
            symmetricKey.cipher().decrypt(ciphertext = data)
        }
    }

    override fun deleteKey(identifier: String) {
        // Delete SE artifacts unconditionally so orphan cleanup works even when this instance
        // has SE disabled; SecItemDelete on a missing item is a harmless no-op.
        keychain.delete(seWrappedAccount(identifier))
        deleteSecureEnclaveKey(seTag(identifier))
        keychain.delete(identifier)
        simulatorFallback?.delete(identifier)
        fallbackServedAliases.remove(identifier)
        keyBytesCache.remove(identifier)
        lastAppliedAccessibility.remove(identifier)
    }

    /** Application tag for the SE EC key pair. */
    private fun seTag(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    /** Keychain account for the SE-wrapped (ECIES-encrypted) AES key. */
    private fun seWrappedAccount(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    /**
     * Creates a new EC P-256 key pair in the Secure Enclave under [tag]. Any existing key at
     * that tag is deleted first — `SecKeyCreateRandomKey` always mints a new one, which would
     * otherwise leave `SecItemCopyMatching` returning the wrong key.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun createSecureEnclaveKey(tag: String, requireUnlockedDevice: Boolean?): SecKeyRef {
        deleteSecureEnclaveKey(tag)
        return autoreleasepool { memScoped {
            val tagData = tagAsNSData(tag)
                ?: throw IllegalStateException("KSafe: Failed to encode SE tag")
            val accessibility = accessibleAttr(resolvedRequireUnlockedDevice(requireUnlockedDevice))

            // null value-callbacks → hold each bridged +1 across SecKeyCreateRandomKey, then
            // release, or they leak on every SE key creation.
            val tagRef = CFBridgingRetain(tagData)
            val keySizeRef = CFBridgingRetain(NSNumber(int = 256))
            val privateKeyAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
                CFDictionarySetValue(this, kSecAttrIsPermanent, kCFBooleanTrue)
                CFDictionarySetValue(this, kSecAttrApplicationTag, tagRef)
                CFDictionarySetValue(this, kSecAttrAccessible, accessibility)
            }
            val attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
                CFDictionarySetValue(this, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
                CFDictionarySetValue(this, kSecAttrKeySizeInBits, keySizeRef)
                CFDictionarySetValue(this, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
                CFDictionarySetValue(this, kSecPrivateKeyAttrs, privateKeyAttrs)
            }

            val keyErrorRef = alloc<CFErrorRefVar>()
            val privateKey = SecKeyCreateRandomKey(attributes, keyErrorRef.ptr)
            CFRelease(privateKeyAttrs as CFTypeRef?)
            CFRelease(attributes as CFTypeRef?)
            CFRelease(tagRef)
            CFRelease(keySizeRef)

            privateKey ?: throw IllegalStateException(
                "KSafe: Failed to create Secure Enclave key: ${cfErrorDescription(keyErrorRef)}"
            )
        } }
    }

    /**
     * The existing SE EC private key for [tag], or `null` if absent. Throws on transient
     * errors (locked device, missing entitlement) so callers don't read them as "not found".
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
     * Unwraps (ECIES-decrypts) AES key bytes with an SE private key. The error preserves the
     * CFError description so callers can tell transient failures from permanent corruption.
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

    /** Raw AES key bytes at [keyId], or `null` if absent; throws on locked/other errors. */
    private fun getExistingKeychainKeyRaw(keyId: String): ByteArray? = keychain.readBytes(keyId)

    /** Test-only: the in-process cached raw key bytes for [keyId], or null. */
    @PublishedApi
    internal fun cachedKeyBytesForTest(keyId: String): ByteArray? = keyBytesCache[keyId]

    /**
     * The existing key for decryption: SE-wrapped account first, then plain, throwing if
     * neither exists (decrypt has no create-on-miss). Hits [keyBytesCache] before any IPC —
     * the cache holds the unwrapped key, so SE keys also skip the ECIES round-trip on a hit.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getExistingKeychainKey(keyId: String, requireUnlockedDevice: Boolean?): ByteArray {
        // Read-only, so it does NOT take keyResolutionLock (that guards the create-vs-create
        // clobber race). Concurrent decrypts of one alias read the same bytes and converge on
        // the thread-safe keyBytesCache (idempotent last-writer-wins).
        if (requireUnlockedDevice != true) {
            keyBytesCache[keyId]?.let { return it }
        } else {
            // Strict read: never serve or keep plaintext from the cache — evict any lingering
            // NON-strict entry so it can't survive after the key was rewritten strict.
            keyBytesCache.remove(keyId)
        }

        // A Simulator fallback key, once minted, wins over the Keychain unconditionally
        // (sticky precedence): every run of an install decrypts with the same key even if
        // the entitlement problem is fixed later.
        simulatorFallback?.read(keyId)?.let { bytes ->
            fallbackKeyServed(keyId)
            if (requireUnlockedDevice != true) {
                keyBytesCache[keyId] = bytes
            }
            return bytes
        }

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
        if (requireUnlockedDevice != true) {
            keyBytesCache[keyId] = bytes
        }
        return bytes
    }

    /**
     * Gets an encryption key, creating one on miss. With [hardwareIsolated] the key is
     * SE-wrapped (ECIES); transient failures propagate, genuine SE-unavailable errors fall
     * back to plain storage. Cache-first: a [keyBytesCache] hit short-circuits the decision.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getOrCreateKeychainKey(
        keyId: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ): ByteArray {
        if (requireUnlockedDevice != true) {
            keyBytesCache[keyId]?.let { return it }
        } else {
            // Strict keys must NEVER keep plaintext in the cache, else a prior NON-strict
            // write's bytes linger after a strict rewrite and defeat the policy in memory.
            keyBytesCache.remove(keyId)
        }

        return withKeyResolutionLock {
            // Re-check under the lock: a concurrent creator may have just populated the cache,
            // in which case reuse its key rather than mint a clobbering one.
            if (requireUnlockedDevice != true) {
                keyBytesCache[keyId]?.let { return@withKeyResolutionLock it }
            }

            val bytes = if (hardwareIsolated) {
                try {
                    getOrCreateKeychainKeyWithSE(keyId, requireUnlockedDevice)
                } catch (e: IllegalStateException) {
                    val msg = e.message ?: ""
                    when {
                        // Must precede the rethrow guards: the -34018 message also
                        // matches their "Keychain error" substring.
                        simulatorFallback != null && isMissingEntitlementFailure(msg) ->
                            getOrCreateKeychainKeyPlain(keyId, requireUnlockedDevice)
                        isTransientUnwrapFailure(msg) ||
                            msg.contains("Keychain error") ||
                            // A store failure is NOT "SE unavailable": don't fall back to a
                            // divergent plain key under the same identifier.
                            msg.contains("Failed to store key in Keychain") -> throw e
                        // SE genuinely unavailable (simulator, old device, no entitlements).
                        else -> getOrCreateKeychainKeyPlain(keyId, requireUnlockedDevice)
                    }
                }
            } else {
                getOrCreateKeychainKeyPlain(keyId, requireUnlockedDevice)
            }
            if (requireUnlockedDevice != true) {
                keyBytesCache[keyId] = bytes
            }
            bytes
        }
    }

    /**
     * SE path, in order: SE-wrapped key (`se.{keyId}`) → unwrap; legacy plain key
     * (`{keyId}`) → return as-is; neither → create a new SE-wrapped key.
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

    /**
     * Plain path — get or create an unwrapped AES key stored directly in the Keychain,
     * or in the Simulator sandbox fallback store when the Keychain rejects this process
     * with `errSecMissingEntitlement` (-34018).
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getOrCreateKeychainKeyPlain(keyId: String, requireUnlockedDevice: Boolean?): ByteArray {
        // Fallback key first — sticky precedence (see getExistingKeychainKey).
        simulatorFallback?.read(keyId)?.let {
            fallbackKeyServed(keyId)
            return it
        }

        val existing = try {
            getExistingKeychainKeyRaw(keyId)
        } catch (e: IllegalStateException) {
            if (simulatorFallback == null || !isMissingEntitlementFailure(e.message)) throw e
            // Mint straight into the sandbox store — storeInKeychain's delete-then-add
            // must not run against a Keychain whose state is unreadable.
            val newKey = secureRandomBytes(keySizeBytes)
            simulatorFallback.write(keyId, newKey)
            fallbackKeyServed(keyId)
            return newKey
        }
        if (existing != null) return existing

        val newKey = secureRandomBytes(keySizeBytes)
        try {
            keychain.store(keyId, newKey, resolvedRequireUnlockedDevice(requireUnlockedDevice))
        } catch (e: IllegalStateException) {
            if (simulatorFallback == null || !isMissingEntitlementFailure(e.message)) throw e
            simulatorFallback.write(keyId, newKey)
            fallbackKeyServed(keyId)
        }
        return newKey
    }

    /**
     * Adds a generic-password item with [keyData] under [keyId], deleting any existing item
     * first so `SecItemAdd` can't duplicate-collision.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun storeInKeychain(keyId: String, keyData: ByteArray, requireUnlockedDevice: Boolean?) {
        autoreleasepool { memScoped {
            val nsData = NSData.create(
                bytes = keyData.refTo(0).getPointer(this),
                length = keyData.size.toULong(),
            )

            usingPasswordQuery(keyId) { deleteQuery -> SecItemDelete(deleteQuery) }

            // null value-callbacks → hold the bridged +1 across SecItemAdd, then release.
            val nsDataRef = CFBridgingRetain(nsData)
            val addStatus = usingPasswordQuery(
                account = keyId,
                configure = { dict ->
                    CFDictionarySetValue(dict, kSecValueData, nsDataRef)
                    CFDictionarySetValue(
                        dict,
                        kSecAttrAccessible,
                        accessibleAttr(resolvedRequireUnlockedDevice(requireUnlockedDevice)),
                    )
                },
            ) { addQuery -> SecItemAdd(addQuery, null) }
            CFRelease(nsDataRef)

            if (addStatus != errSecSuccess) when (addStatus) {
                errSecInteractionNotAllowed -> throw IllegalStateException(
                    "KSafe: Cannot store key in Keychain - device is locked."
                )
                else -> throw IllegalStateException(
                    "KSafe: Failed to store key in Keychain, status: $addStatus${entitlementHint(addStatus)}"
                )
            }
        } }
    }

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    override fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) {
        // Skip the three SecItemUpdate IPC round-trips when the policy is unchanged this
        // process — re-asserting on every write is pure IPC overhead.
        if (!accessibilityUpdateNeeded(lastAppliedAccessibility[identifier], requireUnlocked)) return
        updateKeychainItemAccessibility(identifier, requireUnlocked)
        updateKeychainItemAccessibility(seWrappedAccount(identifier), requireUnlocked)
        updateSecureEnclaveKeyAccessibility(seTag(identifier), requireUnlocked)
        // Record only after all three succeed, so a partial failure retries on the next write.
        lastAppliedAccessibility[identifier] = requireUnlocked
    }

    /**
     * Updates accessibility on the SE-held EC private key — `kSecClassKey`, not
     * generic-password, so it needs its own `SecItemUpdate` query.
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

    /** Runs `SecItemUpdate` with a one-attribute `kSecAttrAccessible` payload, then releases. */
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
