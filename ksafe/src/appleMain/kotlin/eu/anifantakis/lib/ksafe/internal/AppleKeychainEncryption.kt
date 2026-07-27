@file:OptIn(ExperimentalAtomicApi::class)

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
import platform.CoreFoundation.kCFBooleanFalse
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
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Generic-password Keychain operations behind a seam so tests can inject an in-memory fake —
 * real round-trips can't run in the Kotlin/Native test runner (no entitlements).
 */
internal interface AppleKeychainStore {
    /** Bytes at [account], or null if absent. Throws on locked/other Keychain errors. */
    fun readBytes(account: String): ByteArray?

    /** Replaces (delete-then-add) the item at [account]. */
    fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean)

    /** No-op if absent; never throws. */
    fun delete(account: String)
}

internal fun accessibilityUpdateNeeded(lastApplied: Boolean?, target: Boolean): Boolean =
    lastApplied != target

/**
 * Actual custody of one key alias, as [AppleKeychainEncryption.keyCustody] observes it. Lets
 * `getKeyInfo` report what a key IS (an SE request may be served by a legacy plain key, or by
 * the Simulator sandbox file) instead of what was requested. [ABSENT] doubles as "unknown"
 * (no key yet, locked device, Keychain error): callers keep their capability-based inference.
 */
internal enum class AppleKeyCustody { SE_WRAPPED, PLAIN, SIMULATOR_FALLBACK, ABSENT }

/**
 * Apple-platform [KSafeEncryption] over Keychain Services + CryptoKit, shared by iOS,
 * iPadOS and macOS.
 *
 * AES keys are stored as `ThisDeviceOnly` generic-password items (never backed up).
 * With `hardwareIsolated = true` the AES key is envelope-encrypted: an EC P-256 key in
 * the Secure Enclave wraps it via ECIES and only the wrapped key is stored; if the SE is
 * unavailable (simulators, Intel Macs, older devices) the path falls back to plain storage.
 *
 * On the iOS Simulator only, an entitlement-blocked Keychain (`errSecMissingEntitlement`,
 * -34018) additionally falls back to a sandbox file key store instead of failing every
 * encrypted write; see [SimulatorFallbackKeyStore]. Real devices never take that path.
 */
@PublishedApi
internal class AppleKeychainEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val serviceName: String = SERVICE_NAME,
    /** Test seam: in-memory [AppleKeychainStore] for unit tests; null in production. */
    keychainStore: AppleKeychainStore? = null,
    /**
     * Simulator-only escape hatch for an entitlement-blocked Keychain. Defaults to the sandbox
     * file store on the iOS Simulator, null everywhere else. Not auto-enabled when [keychainStore]
     * is a test fake; tests inject their own.
     */
    private val simulatorFallback: SimulatorFallbackKeyStore? =
        if (keychainStore == null && SecurityChecker.isEmulator()) {
            FileSimulatorFallbackKeyStore(serviceName)
        } else {
            null
        },
) : KSafeEncryption {

    private val keychain: AppleKeychainStore = keychainStore ?: RealKeychainStore()

    private inner class RealKeychainStore : AppleKeychainStore {
        override fun readBytes(account: String): ByteArray? = copyKeychainBytes(account)
        override fun store(account: String, bytes: ByteArray, requireUnlocked: Boolean) =
            storeInKeychain(account, bytes, requireUnlocked)
        override fun delete(account: String) = deleteFromKeychain(account)
    }

    companion object {
        private const val SERVICE_NAME = KSAFE_OS_STORE_IDENTITY
        internal const val SE_KEY_TAG_PREFIX = "se."

        /**
         * Whether this device actually has a usable Secure Enclave, probed once per process.
         * Attempts an ephemeral (non-persistent) SE key: it succeeds only where an SE physically
         * exists (real iOS/iPadOS devices, Apple-Silicon / T2 Macs) and fails on SE-less Macs
         * (pre-T2 Intel, VMs) and the Simulator. Replaces the old `!isSimulator()` heuristic, which
         * over-reported SE on every Mac. A transient first-probe failure sticks as `false` for the
         * process — the safe direction: the reported protection never claims stronger isolation than
         * the engine can deliver.
         */
        private val secureEnclaveAvailable: Boolean by lazy { probeSecureEnclave() }

        internal fun deviceHasSecureEnclave(): Boolean = secureEnclaveAvailable

        @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
        private fun probeSecureEnclave(): Boolean = autoreleasepool {
            memScoped {
                val keySizeRef = CFBridgingRetain(NSNumber(int = 256))
                val privateKeyAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
                    // Non-persistent: the probe key is never stored, so nothing to clean up.
                    CFDictionarySetValue(this, kSecAttrIsPermanent, kCFBooleanFalse)
                }
                val errRef = alloc<CFErrorRefVar>()
                // No access-control / biometric gate on the probe key, so this never prompts.
                val key = createSecureEnclaveKeyPair(keySizeRef, privateKeyAttrs, errRef)
                CFRelease(privateKeyAttrs as CFTypeRef?)
                CFRelease(keySizeRef)
                if (key != null) {
                    CFRelease(key)
                    true
                } else {
                    false
                }
            }
        }

        /**
         * `errSecMissingEntitlement`. Local constant; the Kotlin platform libs don't re-export
         * this symbol.
         */
        internal const val ERR_SEC_MISSING_ENTITLEMENT = -34018

        // Every engine throw site embeds the raw numeric status, so the substring match is exact.
        internal fun isMissingEntitlementFailure(message: String?): Boolean =
            message?.contains(ERR_SEC_MISSING_ENTITLEMENT.toString()) == true

        internal fun entitlementHint(status: Int): String =
            if (status == ERR_SEC_MISSING_ENTITLEMENT) {
                " (errSecMissingEntitlement: the process has no Keychain entitlement — " +
                    "select a signing team and/or add the Keychain Sharing capability in " +
                    "Xcode; on the iOS Simulator also try Device > Erase All Content and Settings)"
            } else {
                ""
            }

        /** Keychain account lookup order for a key id: SE-wrapped first, then legacy plain. */
        internal fun keychainLookupOrder(keyId: String): List<String> =
            listOf("$SE_KEY_TAG_PREFIX$keyId", keyId)

        /**
         * OSStatus codes whose SE/unwrap failure is transient (NOT corruption): the SE key must
         * be preserved and the error propagated rather than regenerated.
         */
        private val TRANSIENT_OSSTATUS: Set<Long> = setOf(
            errSecInteractionNotAllowed.toLong(), // -25308: device locked
            errSecNotAvailable.toLong(),          // -25291: keychain/securityd not ready
            errSecAuthFailed.toLong(),            // -25293: auth failed (retryable)
            errSecUserCanceled.toLong(),          // -128: user cancelled the auth prompt
        )

        private val OSSTATUS_TAG = Regex("""osstatus=(-?\d+)""")

        /**
         * True when an unwrap/SE error is transient and should propagate rather than trigger
         * destructive cleanup. Keys on the locale-independent `[osstatus=<code>]` tag; the
         * English-substring check is only a fallback for messages carrying no tag.
         */
        internal fun isTransientUnwrapFailure(message: String?): Boolean {
            val msg = message ?: return false
            val code = OSSTATUS_TAG.find(msg)?.groupValues?.get(1)?.toLongOrNull()
            if (code != null && code in TRANSIENT_OSSTATUS) return true
            return msg.contains(KSafeEngineMessage.DEVICE_LOCKED, ignoreCase = true) ||
                msg.contains("interaction", ignoreCase = true)
        }

        /**
         * SE wrap/unwrap failure message. A transient [detail] gets the " [transient Keychain
         * failure]" marker the core's top-level `isTransientDecryptFailure`
         * (`internal.coreparts.KSafeCoreFailureClassification`) matches on the DECRYPT path —
         * without it a transient unwrap is misclassified permanent and `getDirect` silently
         * returns the caller's default.
         */
        internal fun seFailureMessage(op: String, detail: String): String {
            val transientBrand =
                if (isTransientUnwrapFailure(detail)) " [transient Keychain failure]" else ""
            return "KSafe: Failed to $op AES key with Secure Enclave: $detail$transientBrand"
        }
    }

    private val keySizeBytes: Int = config.keySize / 8

    /**
     * In-process cache of unwrapped raw AES key bytes by `keyId`. Keychain bytes are immutable
     * for an alias's lifetime, so this is invalidated only via [deleteKey], never by
     * accessibility updates (which preserve the bytes).
     */
    private val keyBytesCache = KSafeConcurrentMap<ByteArray>()

    /**
     * Purge epoch for [keyBytesCache], bumped by [deleteKey] both before and after its deletions.
     * The read path is lock-free and shares no per-alias monitor with [deleteKey], so a reader
     * that copied key bytes just before a `clearAll`/sweep delete could re-insert them AFTER the
     * purge — leaving RAM-only material with no Keychain item behind it (readable all session,
     * unreadable after relaunch, since post-clearAll DEFAULT writes reuse the same master alias).
     */
    private val keyBytesCacheEpoch = AtomicLong(0)

    private fun cacheKeyBytes(keyId: String, bytes: ByteArray, epochAtRead: Long) =
        insertUnderPurgeFence(keyBytesCache, keyBytesCacheEpoch, keyId, bytes, epochAtRead)

    /**
     * The warm key bytes for [keyId], or null. A strict lookup must never serve OR keep plaintext
     * from the cache, so it also evicts any lingering non-strict entry — otherwise a prior relaxed
     * write's bytes survive a strict rewrite and defeat the lock policy in memory.
     */
    private fun cachedKeyBytesOrEvict(keyId: String, requireUnlockedDevice: Boolean?): ByteArray? {
        if (requireUnlockedDevice == true) {
            keyBytesCache.remove(keyId)
            return null
        }
        return keyBytesCache[keyId]
    }

    /** [cachedKeyBytesOrEvict]'s write half: strict key bytes are never retained. */
    private fun maybeCacheKeyBytes(
        keyId: String,
        bytes: ByteArray,
        epochAtRead: Long,
        requireUnlockedDevice: Boolean?,
    ) {
        if (requireUnlockedDevice != true) cacheKeyBytes(keyId, bytes, epochAtRead)
    }

    /**
     * Last `requireUnlocked` accessibility applied per key-id this process, letting
     * [updateKeyAccessibility] skip its three `SecItemUpdate` IPC round-trips when unchanged.
     * Set only after all three succeed, so a partial failure retries on the next write.
     */
    private val lastAppliedAccessibility = KSafeConcurrentMap<Boolean>()

    /**
     * Aliases served from [simulatorFallback] this process. Lets [encrypt] skip the accessibility
     * `SecItemUpdate` IPC for fallback keys (the Keychain would reject it with -34018 every write)
     * and feeds the `protectionInfo` degrade report.
     */
    private val fallbackServedAliases = KSafeConcurrentMap<Boolean>()
    private val fallbackActivated = KSafeAtomicFlag(false)
    private val fallbackWarned = KSafeAtomicFlag(false)

    internal fun isSimulatorFallbackActive(): Boolean = fallbackActivated.get()

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
     * the delete-then-add `storeInKeychain` lets the second clobber the first after the first
     * already produced ciphertext under its key — permanently losing that data. Reentrant so the
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

    @OptIn(ExperimentalForeignApi::class)
    private fun accessibleAttr(requireUnlocked: Boolean): CFTypeRef? =
        if (requireUnlocked) kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        else kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    @OptIn(BetaInteropApi::class)
    private fun tagAsNSData(tag: String): NSData? =
        (tag as NSString).dataUsingEncoding(NSUTF8StringEncoding)

    /**
     * Description out of a CFError. For OSStatus-domain errors it appends a locale-independent
     * `[osstatus=<code>]` tag so transient-vs-permanent classification keys on the numeric code,
     * not the localized text (which on a non-English device would misclassify a transient
     * locked-device failure as permanent and trigger destructive key regeneration).
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun cfErrorDescription(errorRef: CFErrorRefVar): String {
        val cfError = errorRef.value ?: return "no error details"
        val nsError = CFBridgingRelease(cfError) as? platform.Foundation.NSError
            ?: return "unknown error"
        val desc = nsError.localizedDescription
        return if (nsError.domain == NSOSStatusErrorDomain) "$desc [osstatus=${nsError.code}]" else desc
    }

    /** `kSecClassGenericPassword` query for [account]; [configure] adds attributes, releases on exit. */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private inline fun <R> usingPasswordQuery(
        account: String,
        configure: (CFMutableDictionaryRef?) -> Unit = {},
        block: (CFMutableDictionaryRef?) -> R,
    ): R {
        val dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        // null value-callbacks → the dict does NOT retain its values: hold each CFBridgingRetain
        // +1 across [block], then release, or every value leaks a pair per call.
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
        // null value-callbacks → hold the bridged +1 across [block], then release, or it leaks.
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

    /** Bytes at [account], `null` on not-found, throwing on transient/unexpected statuses. */
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
                        "KSafe: Cannot access ${KSafeEngineMessage.KEYCHAIN} - ${KSafeEngineMessage.DEVICE_LOCKED}. " +
                            "Key exists but is inaccessible."
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
        aad: ByteArray?,
    ): ByteArray {
        // Bounded retry around a sibling-instance key deletion (clearAll) racing this encrypt:
        // the bytes were resolved, the Keychain item deleted, and the acknowledged ciphertext
        // would be unreadable next launch. The epoch moves on ANY alias deletion, so an
        // unchanged-epoch fast path returns immediately; on a bump the alias is re-read —
        // same bytes means the deletion targeted another alias, otherwise the loop re-resolves
        // through the proper route (Keychain/SE envelope) and re-encrypts under the winner.
        repeat(2) {
            val epochAtResolve = keyBytesCacheEpoch.load()
            val keyBytes = getOrCreateKeychainKey(identifier, hardwareIsolated, requireUnlockedDevice)
            // Strict and relaxed HARDWARE_ISOLATED writes use different aliases since the strict
            // variant (a policy transition mints a fresh item with the right accessibility), so
            // this re-assert is normally an idempotent no-op; it still matters for LEGACY
            // marker-less strict items living on the bare alias, and stays direction-aware:
            // tightening is fail-closed — swallowing the failure would commit strict metadata
            // over an item the Keychain still serves while locked, so the write fails instead
            // (a missing item is tolerated: the update treats errSecItemNotFound as done).
            // Loosening stays best-effort — a failure leaves the item STRICTER than declared, and
            // the next write retries. Skipped for Simulator-fallback keys — no Keychain item, IPC
            // re-fails -34018.
            if (hardwareIsolated && fallbackServedAliases[identifier] != true) {
                val targetRequireUnlocked = config.resolveRequireUnlockedDevice(requireUnlockedDevice)
                if (targetRequireUnlocked) updateKeyAccessibility(identifier, true)
                else runCatching { updateKeyAccessibility(identifier, false) }
            }
            val out = cryptoKitEncrypt(keyBytes, data, aad)
            if (keyBytesCacheEpoch.load() == epochAtResolve) return out
            val current = runCatching { getExistingKeychainKey(identifier, requireUnlockedDevice) }.getOrNull()
            if (current != null && current.contentEquals(keyBytes)) return out
        }
        return cryptoKitEncrypt(
            getOrCreateKeychainKey(identifier, hardwareIsolated, requireUnlockedDevice), data, aad,
        )
    }

    private fun cryptoKitEncrypt(keyBytes: ByteArray, data: ByteArray, aad: ByteArray?): ByteArray =
        runBlocking {
            val aesGcm = CryptographyProvider.CryptoKit.get(AES.GCM)
            val symmetricKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, keyBytes)
            if (aad != null) symmetricKey.cipher().encrypt(plaintext = data, associatedData = aad)
            else symmetricKey.cipher().encrypt(plaintext = data)
        }

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray {
        val keyBytes = getExistingKeychainKey(identifier, requireUnlockedDevice)
        return runBlocking {
            val aesGcm = CryptographyProvider.CryptoKit.get(AES.GCM)
            val symmetricKey = aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, keyBytes)
            if (aad != null) symmetricKey.cipher().decrypt(ciphertext = data, associatedData = aad)
            else symmetricKey.cipher().decrypt(ciphertext = data)
        }
    }

    override fun deleteKey(identifier: String) {
        // Fence FIRST (see [keyBytesCacheEpoch]): any lock-free reader mid-resolution must
        // observe the bump and refuse to re-cache the bytes it read before these deletions.
        keyBytesCacheEpoch.addAndFetch(1)
        // Delete SE artifacts unconditionally so orphan cleanup works even with SE disabled.
        keychain.delete(seWrappedAccount(identifier))
        deleteSecureEnclaveKey(seTag(identifier))
        keychain.delete(identifier)
        simulatorFallback?.delete(identifier)
        fallbackServedAliases.remove(identifier)
        // Second fence: closes the window where a reader that captured the epoch post-first-bump
        // re-inserts bytes read pre-deletion only now — a single bump wouldn't catch that insert.
        keyBytesCacheEpoch.addAndFetch(1)
        keyBytesCache.remove(identifier)
        lastAppliedAccessibility.remove(identifier)
    }

    private fun seTag(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    private fun seWrappedAccount(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    /**
     * Creates a new EC P-256 key pair in the Secure Enclave under [tag]. Any existing key at that
     * tag is deleted first — `SecKeyCreateRandomKey` always mints a new one, else
     * `SecItemCopyMatching` would return the wrong key.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun createSecureEnclaveKey(tag: String, requireUnlockedDevice: Boolean?): SecKeyRef {
        deleteSecureEnclaveKey(tag)
        return autoreleasepool { memScoped {
            val tagData = tagAsNSData(tag)
                ?: throw IllegalStateException("KSafe: Failed to encode SE tag")
            val accessibility = accessibleAttr(config.resolveRequireUnlockedDevice(requireUnlockedDevice))

            // null value-callbacks → hold each bridged +1 across SecKeyCreateRandomKey, then release.
            val tagRef = CFBridgingRetain(tagData)
            val keySizeRef = CFBridgingRetain(NSNumber(int = 256))
            val privateKeyAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
                CFDictionarySetValue(this, kSecAttrIsPermanent, kCFBooleanTrue)
                CFDictionarySetValue(this, kSecAttrApplicationTag, tagRef)
                CFDictionarySetValue(this, kSecAttrAccessible, accessibility)
            }
            val keyErrorRef = alloc<CFErrorRefVar>()
            val privateKey = createSecureEnclaveKeyPair(keySizeRef, privateKeyAttrs, keyErrorRef)
            CFRelease(privateKeyAttrs as CFTypeRef?)
            CFRelease(tagRef)
            CFRelease(keySizeRef)

            privateKey ?: throw IllegalStateException(
                "KSafe: Failed to create Secure Enclave key: ${cfErrorDescription(keyErrorRef)}"
            )
        } }
    }

    /**
     * The existing SE EC private key for [tag], or `null` if absent. Throws on transient errors
     * so callers don't read them as "not found".
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
                        "KSafe: Cannot access Secure Enclave key - ${KSafeEngineMessage.DEVICE_LOCKED}."
                    )
                    else -> throw IllegalStateException(
                        "KSafe: Keychain error $status retrieving SE key for tag $tag"
                    )
                }
            }
        } }

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
        // autoreleasepool: Kotlin/Native worker threads have no ambient pool; the autoreleased
        // ObjC objects each SE op bridges would otherwise grow native memory unbounded on a hot
        // strict-read loop (getExistingKeychainKey reaches here without a pool).
        autoreleasepool { memScoped {
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
        } }

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun deleteSecureEnclaveKey(tag: String) {
        autoreleasepool { memScoped {
            val tagData = tagAsNSData(tag) ?: return@autoreleasepool
            usingSeKeyQuery(tagData) { query -> SecItemDelete(query) }
        } }
    }

    private fun getExistingKeychainKeyRaw(keyId: String): ByteArray? = keychain.readBytes(keyId)

    /**
     * Where the key material for [keyId] actually lives right now, probed in the same order the
     * decrypt path resolves it (sticky Simulator fallback, SE-wrapped account, plain item).
     * Diagnostics only: any Keychain failure (locked device, transient error) reads as
     * [AppleKeyCustody.ABSENT] so callers fall back to capability inference instead of throwing.
     */
    internal fun keyCustody(keyId: String): AppleKeyCustody = try {
        when {
            simulatorFallback?.read(keyId) != null -> AppleKeyCustody.SIMULATOR_FALLBACK
            getExistingKeychainKeyRaw(seWrappedAccount(keyId)) != null -> AppleKeyCustody.SE_WRAPPED
            getExistingKeychainKeyRaw(keyId) != null -> AppleKeyCustody.PLAIN
            else -> AppleKeyCustody.ABSENT
        }
    } catch (_: Throwable) {
        AppleKeyCustody.ABSENT
    }

    @PublishedApi
    internal fun cachedKeyBytesForTest(keyId: String): ByteArray? = keyBytesCache[keyId]

    /**
     * The existing key for decryption: SE-wrapped account first, then plain, throwing if neither
     * exists. Hits [keyBytesCache] before any IPC — the cache holds the unwrapped key, so SE keys
     * also skip the ECIES round-trip on a hit.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getExistingKeychainKey(keyId: String, requireUnlockedDevice: Boolean?): ByteArray {
        // Read-only, so it does NOT take keyResolutionLock (that guards the create-vs-create
        // clobber race); concurrent decrypts converge on the thread-safe keyBytesCache.
        cachedKeyBytesOrEvict(keyId, requireUnlockedDevice)?.let { return it }
        val epochAtRead = keyBytesCacheEpoch.load()

        // A Simulator fallback key, once minted, wins over the Keychain unconditionally (sticky
        // precedence), even if the entitlement problem is fixed later.
        simulatorFallback?.read(keyId)?.let { bytes ->
            fallbackKeyServed(keyId)
            maybeCacheKeyBytes(keyId, bytes, epochAtRead, requireUnlockedDevice)
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
                ?: throw IllegalStateException(KSafeEngineMessage.noKeyFound(keyId))
        }
        maybeCacheKeyBytes(keyId, bytes, epochAtRead, requireUnlockedDevice)
        return bytes
    }

    /**
     * Gets an encryption key, creating one on miss. With [hardwareIsolated] the key is SE-wrapped
     * (ECIES); transient failures propagate, genuine SE-unavailable errors fall back to plain.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getOrCreateKeychainKey(
        keyId: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ): ByteArray {
        cachedKeyBytesOrEvict(keyId, requireUnlockedDevice)?.let { return it }

        return withKeyResolutionLock {
            // Re-check under the lock: a concurrent creator may have just populated the cache.
            // The strict eviction already happened above, so this is a plain cache read.
            if (requireUnlockedDevice != true) {
                keyBytesCache[keyId]?.let { return@withKeyResolutionLock it }
            }
            val epochAtRead = keyBytesCacheEpoch.load()

            val bytes = if (hardwareIsolated) {
                try {
                    getOrCreateKeychainKeyWithSE(keyId, requireUnlockedDevice)
                } catch (e: IllegalStateException) {
                    val msg = e.message ?: ""
                    when {
                        // Must precede the rethrow guards: -34018 also matches "Keychain error".
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
            maybeCacheKeyBytes(keyId, bytes, epochAtRead, requireUnlockedDevice)
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
                // SE key gone — the wrapped blob is unusable.
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
                keychain.store(seWrappedAccount(keyId), wrapped, config.resolveRequireUnlockedDevice(requireUnlockedDevice))
                return newAesKey
            } finally {
                CFRelease(sePublicKey)
            }
        } finally {
            CFRelease(sePrivateKey)
        }
    }

    /**
     * Plain path — get or create an unwrapped AES key stored directly in the Keychain, or in the
     * Simulator sandbox fallback store when the Keychain rejects this process with -34018.
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
            // Mint straight into the sandbox store — the delete-then-add must not run against a
            // Keychain whose state is unreadable.
            val newKey = secureRandomBytes(keySizeBytes)
            simulatorFallback.write(keyId, newKey)
            fallbackKeyServed(keyId)
            return newKey
        }
        if (existing != null) return existing

        val newKey = secureRandomBytes(keySizeBytes)
        try {
            keychain.store(keyId, newKey, config.resolveRequireUnlockedDevice(requireUnlockedDevice))
        } catch (e: IllegalStateException) {
            if (simulatorFallback == null || !isMissingEntitlementFailure(e.message)) throw e
            simulatorFallback.write(keyId, newKey)
            fallbackKeyServed(keyId)
        }
        return newKey
    }

    /**
     * Adds a generic-password item under [keyId], deleting any existing item first so `SecItemAdd`
     * can't duplicate-collision.
     */
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun storeInKeychain(keyId: String, keyData: ByteArray, requireUnlockedDevice: Boolean?) {
        autoreleasepool { memScoped {
            val nsData = NSData.create(
                bytes = keyData.refTo(0).getPointer(this),
                length = keyData.size.toULong(),
            )

            usingPasswordQuery(keyId) { deleteQuery -> SecItemDelete(deleteQuery) }

            val nsDataRef = CFBridgingRetain(nsData)
            val addStatus = usingPasswordQuery(
                account = keyId,
                configure = { dict ->
                    CFDictionarySetValue(dict, kSecValueData, nsDataRef)
                    CFDictionarySetValue(
                        dict,
                        kSecAttrAccessible,
                        accessibleAttr(config.resolveRequireUnlockedDevice(requireUnlockedDevice)),
                    )
                },
            ) { addQuery -> SecItemAdd(addQuery, null) }
            CFRelease(nsDataRef)

            if (addStatus != errSecSuccess) when (addStatus) {
                errSecInteractionNotAllowed -> throw IllegalStateException(
                    "KSafe: Cannot store key in ${KSafeEngineMessage.KEYCHAIN} - ${KSafeEngineMessage.DEVICE_LOCKED}."
                )
                else -> throw IllegalStateException(
                    "KSafe: Failed to store key in Keychain, status: $addStatus${entitlementHint(addStatus)}"
                )
            }
        } }
    }

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    override fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) {
        if (!accessibilityUpdateNeeded(lastAppliedAccessibility[identifier], requireUnlocked)) return
        updateKeychainItemAccessibility(identifier, requireUnlocked)
        updateKeychainItemAccessibility(seWrappedAccount(identifier), requireUnlocked)
        updateSecureEnclaveKeyAccessibility(seTag(identifier), requireUnlocked)
        // Record only after all three succeed, so a partial failure retries on the next write.
        lastAppliedAccessibility[identifier] = requireUnlocked
    }

    /**
     * Accessibility on the SE-held EC private key — `kSecClassKey`, not generic-password, so it
     * needs its own `SecItemUpdate` query.
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
            handleAccessibilityUpdateStatus(status, KSafeEngineMessage.KEYCHAIN)
        } }
    }

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
                "KSafe: Cannot update $what accessibility - ${KSafeEngineMessage.DEVICE_LOCKED}."
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

    @OptIn(ExperimentalForeignApi::class)
    private fun NSData.toByteArray(): ByteArray {
        val len = this.length.toInt()
        // addressOf(0) throws on a zero-length ByteArray; a zero-length Keychain item (externally
        // created/corrupted — KSafe never writes empty blobs) must read as empty, not crash.
        if (len == 0) return ByteArray(0)
        return ByteArray(len).apply {
            usePinned {
                memcpy(it.addressOf(0), this@toByteArray.bytes, this@toByteArray.length)
            }
        }
    }
}

/**
 * Mints one Secure Enclave EC P-256 key pair from [privateKeyAttrs], owning the outer attribute
 * dictionary's lifetime. Top-level because both callers need it and they sit on opposite sides of
 * the companion boundary — and because manual CoreFoundation refcounting is where a second copy
 * turns into a leak or a double free. The caller keeps ownership of [keySizeRef] and
 * [privateKeyAttrs]; the dictionary is created with null value-callbacks, so it retains neither.
 */
@OptIn(ExperimentalForeignApi::class)
private fun createSecureEnclaveKeyPair(
    keySizeRef: CFTypeRef?,
    privateKeyAttrs: CFMutableDictionaryRef?,
    errRef: CFErrorRefVar,
): SecKeyRef? {
    val attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
        CFDictionarySetValue(this, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionarySetValue(this, kSecAttrKeySizeInBits, keySizeRef)
        CFDictionarySetValue(this, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
        CFDictionarySetValue(this, kSecPrivateKeyAttrs, privateKeyAttrs)
    }
    return try {
        SecKeyCreateRandomKey(attributes, errRef.ptr)
    } finally {
        CFRelease(attributes as CFTypeRef?)
    }
}
