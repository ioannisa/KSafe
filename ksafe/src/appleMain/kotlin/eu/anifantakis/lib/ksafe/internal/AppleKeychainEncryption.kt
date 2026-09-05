@file:OptIn(ExperimentalAtomicApi::class)

package eu.anifantakis.lib.ksafe.internal

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
import platform.Security.errSecDecode
import platform.Security.errSecInteractionNotAllowed
import platform.Security.errSecItemNotFound
import platform.Security.errSecNotAvailable
import platform.Security.errSecParam
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

// Seam so tests can inject an in-memory fake; real round-trips need entitlements the test runner
// has no way to grant.
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

// What a key alias IS right now, so `getKeyInfo` reports actual custody rather than what was
// requested. ABSENT doubles as "unknown" (no key, locked device, Keychain error).
internal enum class AppleKeyCustody { SE_WRAPPED, PLAIN, SIMULATOR_FALLBACK, ABSENT }

/**
 * Apple [KSafeEncryption] over Keychain Services + CryptoKit (iOS, iPadOS, macOS). AES keys live
 * as `ThisDeviceOnly` generic-password items; with `hardwareIsolated = true` a Secure Enclave EC
 * key wraps them via ECIES, falling back to plain storage where no SE exists. On the iOS Simulator
 * an entitlement-blocked Keychain (-34018) falls back to a sandbox file store instead.
 */
@PublishedApi
internal class AppleKeychainEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val serviceName: String = SERVICE_NAME,
    keychainStore: AppleKeychainStore? = null,
    /** Simulator-only escape hatch for an entitlement-blocked Keychain; null everywhere else. */
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

        // Probed once by minting an ephemeral SE key. A transient first-probe failure sticks as
        // false for the process — never claim stronger isolation than the engine can deliver.
        private val secureEnclaveAvailable: Boolean by lazy { probeSecureEnclave() }

        internal fun deviceHasSecureEnclave(): Boolean = secureEnclaveAvailable

        @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
        private fun probeSecureEnclave(): Boolean = autoreleasepool {
            memScoped {
                val keySizeRef = CFBridgingRetain(NSNumber(int = 256))
                val privateKeyAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null).apply {
                    CFDictionarySetValue(this, kSecAttrIsPermanent, kCFBooleanFalse)
                }
                val errRef = alloc<CFErrorRefVar>()
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

        /** `errSecMissingEntitlement`; the Kotlin platform libs don't re-export this symbol. */
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

        internal fun keychainLookupOrder(keyId: String): List<String> =
            listOf("$SE_KEY_TAG_PREFIX$keyId", keyId)

        private val TRANSIENT_OSSTATUS: Set<Long> = setOf(
            errSecInteractionNotAllowed.toLong(), // -25308: device locked
            errSecNotAvailable.toLong(),          // -25291: keychain/securityd not ready
            errSecAuthFailed.toLong(),            // -25293: auth failed (retryable)
            errSecUserCanceled.toLong(),          // -128: user cancelled the auth prompt
        )

        private val OSSTATUS_TAG = Regex("""osstatus=(-?\d+)""")

        // Keys on the locale-independent `[osstatus=<code>]` tag; the English-substring check is
        // only a fallback for messages carrying no tag.
        internal fun isTransientUnwrapFailure(message: String?): Boolean {
            val msg = message ?: return false
            val code = OSSTATUS_TAG.find(msg)?.groupValues?.get(1)?.toLongOrNull()
            if (code != null && code in TRANSIENT_OSSTATUS) return true
            return msg.contains(KSafeEngineMessage.DEVICE_LOCKED, ignoreCase = true) ||
                msg.contains("interaction", ignoreCase = true)
        }

        /** Codes that prove the wrapped blob is unusable, so replacing it loses nothing readable. */
        private val CORRUPT_ENVELOPE_OSSTATUS: Set<Long> = setOf(
            errSecDecode.toLong(), // -26275: the blob does not decode
            errSecParam.toLong(),  // -50: the blob is not a valid envelope for this key
        )

        /** True only on positive proof; an unknown code or an untagged CFError must not destroy the SE key pair. */
        internal fun isProvablyCorruptEnvelope(message: String?): Boolean {
            val code = OSSTATUS_TAG.find(message ?: return false)?.groupValues?.get(1)?.toLongOrNull()
            return code != null && code in CORRUPT_ENVELOPE_OSSTATUS
        }

        // The transient marker is what the core's decrypt-path classifier matches; without it a
        // transient unwrap reads as permanent and getDirect silently returns the caller's default.
        internal fun seFailureMessage(op: String, detail: String): String {
            val transientBrand =
                if (isTransientUnwrapFailure(detail)) " [transient Keychain failure]" else ""
            return "KSafe: Failed to $op AES key with Secure Enclave: $detail$transientBrand"
        }
    }

    private val keySizeBytes: Int = config.aesKeySize.bytes

    // Keychain bytes are immutable per alias, so only deleteKey invalidates this.
    private val keyBytesCache = KSafeConcurrentMap<ByteArray>()

    // Purge fence: the read path is lock-free, so a reader that copied bytes before a clearAll
    // delete could re-insert them after the purge, leaving key material with no Keychain item.
    private val keyBytesCacheEpoch = AtomicLong(0)

    private fun cacheKeyBytes(keyId: String, bytes: ByteArray, epochAtRead: Long) =
        insertUnderPurgeFence(keyBytesCache, keyBytesCacheEpoch, keyId, bytes, epochAtRead)

    // A strict lookup must neither serve nor keep cached plaintext, so it evicts any relaxed entry;
    // otherwise a prior relaxed write's bytes survive a strict rewrite and defeat the lock policy.
    private fun cachedKeyBytesOrEvict(keyId: String, requireUnlockedDevice: Boolean?): ByteArray? {
        if (requireUnlockedDevice == true) {
            keyBytesCache.remove(keyId)
            return null
        }
        return keyBytesCache[keyId]
    }

    private fun maybeCacheKeyBytes(
        keyId: String,
        bytes: ByteArray,
        epochAtRead: Long,
        requireUnlockedDevice: Boolean?,
    ) {
        if (requireUnlockedDevice != true) cacheKeyBytes(keyId, bytes, epochAtRead)
    }

    // Last accessibility applied per key-id, to skip three SecItemUpdate round-trips when unchanged.
    private val lastAppliedAccessibility = KSafeConcurrentMap<Boolean>()

    // Aliases served from simulatorFallback this process: encrypt skips the accessibility IPC for
    // them (the Keychain would reject it with -34018) and protectionInfo reports the degrade.
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

    // Serializes cache-miss → look up / create → store → cache. Without it two threads both see
    // errSecItemNotFound, both mint a key, and the delete-then-add store lets the second clobber
    // ciphertext already written under the first. Reentrant: the nested helpers re-enter it.
    private val keyResolutionLock = NSRecursiveLock()

    @OptIn(ExperimentalForeignApi::class)
    private inline fun <R> withKeyResolutionLock(block: () -> R): R =
        // Kotlin/Native worker threads have no ambient autorelease pool, so the NSRecursiveLock
        // bridging would leak without one.
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

    // The `[osstatus=<code>]` tag keeps transient-vs-permanent classification off the localized
    // text; on a non-English device a locked device would otherwise read as permanent.
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun cfErrorDescription(errorRef: CFErrorRefVar): String {
        val cfError = errorRef.value ?: return "no error details"
        val nsError = CFBridgingRelease(cfError) as? platform.Foundation.NSError
            ?: return "unknown error"
        val desc = nsError.localizedDescription
        return if (nsError.domain == NSOSStatusErrorDomain) "$desc [osstatus=${nsError.code}]" else desc
    }

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private inline fun <R> usingPasswordQuery(
        account: String,
        configure: (CFMutableDictionaryRef?) -> Unit = {},
        block: (CFMutableDictionaryRef?) -> R,
    ): R {
        val dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        // null value-callbacks → the dict does not retain its values: hold each bridged +1 across
        // the block, then release, or every value leaks.
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

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private inline fun <R> usingSeKeyQuery(
        tagData: NSData,
        configure: (CFMutableDictionaryRef?) -> Unit = {},
        block: (CFMutableDictionaryRef?) -> R,
    ): R {
        val dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, null, null)
        // null value-callbacks → hold the bridged +1 across the block, then release, or it leaks.
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
        // Bounded retry for a sibling clearAll racing this encrypt: the key bytes resolve, the
        // Keychain item is deleted, and the acknowledged ciphertext would be unreadable next
        // launch. Unchanged epoch = no deletion; a bump re-reads and re-encrypts under the winner.
        repeat(2) {
            val epochAtResolve = keyBytesCacheEpoch.load()
            val keyBytes = getOrCreateKeychainKey(identifier, hardwareIsolated, requireUnlockedDevice)
            // Tightening is fail-closed: a swallowed failure would commit strict metadata over an
            // item the Keychain still serves while locked. Loosening stays best-effort. Skipped for
            // Simulator-fallback keys — there is no Keychain item and the IPC re-fails -34018.
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
        AppleAesGcm.encrypt(keyBytes, data, authenticatedData = aad)

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray {
        val keyBytes = getExistingKeychainKey(identifier, requireUnlockedDevice)
        return AppleAesGcm.decrypt(keyBytes, data, authenticatedData = aad)
    }

    override fun deleteKey(identifier: String) {
        // Fence FIRST: a lock-free reader mid-resolution must see the bump and refuse to re-cache
        // the bytes it read before these deletions.
        keyBytesCacheEpoch.addAndFetch(1)
        // Delete SE artifacts unconditionally so orphan cleanup works even with SE disabled.
        keychain.delete(seWrappedAccount(identifier))
        deleteSecureEnclaveKey(seTag(identifier))
        keychain.delete(identifier)
        simulatorFallback?.delete(identifier)
        fallbackServedAliases.remove(identifier)
        // Second fence: a reader that captured the epoch after the first bump could still insert
        // pre-deletion bytes now; one bump wouldn't catch it.
        keyBytesCacheEpoch.addAndFetch(1)
        keyBytesCache.remove(identifier)
        lastAppliedAccessibility.remove(identifier)
    }

    private fun seTag(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    private fun seWrappedAccount(keyId: String): String = "$SE_KEY_TAG_PREFIX$keyId"

    // Deletes any key at [tag] first: SecKeyCreateRandomKey always mints a new one, so a stale item
    // would be what SecItemCopyMatching later returns.
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun createSecureEnclaveKey(tag: String, requireUnlockedDevice: Boolean?): SecKeyRef {
        deleteSecureEnclaveKey(tag)
        return autoreleasepool { memScoped {
            val tagData = tagAsNSData(tag)
                ?: throw IllegalStateException("KSafe: Failed to encode SE tag")
            val accessibility = accessibleAttr(config.resolveRequireUnlockedDevice(requireUnlockedDevice))

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

    // Throws on transient errors so callers don't read them as "not found".
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

    // The thrown error keeps the CFError description so callers can tell transient from corrupt.
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun unwrapAesKey(privateKey: SecKeyRef, wrappedBytes: ByteArray): ByteArray =
        cryptWithSeKey(privateKey, wrappedBytes, wrap = false)

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun cryptWithSeKey(key: SecKeyRef, input: ByteArray, wrap: Boolean): ByteArray =
        // Kotlin/Native worker threads have no ambient pool; without this the ObjC objects each SE
        // op bridges grow native memory unbounded on a hot strict-read loop.
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

    // Probed in the order the decrypt path resolves. Diagnostics only: any Keychain failure reads
    // as ABSENT so callers fall back to capability inference instead of throwing.
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

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getExistingKeychainKey(keyId: String, requireUnlockedDevice: Boolean?): ByteArray {
        // Read-only: no keyResolutionLock (that guards the create-vs-create clobber); concurrent
        // decrypts converge on the thread-safe keyBytesCache.
        cachedKeyBytesOrEvict(keyId, requireUnlockedDevice)?.let { return it }
        val epochAtRead = keyBytesCacheEpoch.load()

        // A minted Simulator fallback key wins over the Keychain for good, even once the
        // entitlement problem is fixed.
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

    // With [hardwareIsolated] the key is SE-wrapped; failures on an existing key propagate, only
    // genuine SE-unavailable errors fall back to plain.
    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    internal fun getOrCreateKeychainKey(
        keyId: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ): ByteArray {
        cachedKeyBytesOrEvict(keyId, requireUnlockedDevice)?.let { return it }

        return withKeyResolutionLock {
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
                            // Neither an unwrap nor a store failure means "SE unavailable": falling
                            // back would downgrade the alias to a divergent plain key.
                            msg.contains("Failed to unwrap AES key with Secure Enclave") ||
                            msg.contains("Failed to store key in Keychain") -> throw e
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

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getOrCreateKeychainKeyWithSE(keyId: String, requireUnlockedDevice: Boolean?): ByteArray {
        val wrappedBytes = getExistingKeychainKeyRaw(seWrappedAccount(keyId))
        if (wrappedBytes != null) {
            val sePrivateKey = getSecureEnclaveKey(seTag(keyId))
            if (sePrivateKey != null) {
                try {
                    return unwrapAesKey(sePrivateKey, wrappedBytes)
                } catch (e: IllegalStateException) {
                    if (!isProvablyCorruptEnvelope(e.message)) throw e
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

    @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
    private fun getOrCreateKeychainKeyPlain(keyId: String, requireUnlockedDevice: Boolean?): ByteArray {
        // Fallback key first — sticky precedence, as in getExistingKeychainKey.
        simulatorFallback?.read(keyId)?.let {
            fallbackKeyServed(keyId)
            return it
        }

        val existing = try {
            getExistingKeychainKeyRaw(keyId)
        } catch (e: IllegalStateException) {
            if (simulatorFallback == null || !isMissingEntitlementFailure(e.message)) throw e
            // Mint straight into the sandbox store: the delete-then-add must not run against a
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

    // Deletes any existing item first so SecItemAdd can't duplicate-collision.
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

    // The SE private key is kSecClassKey, not generic-password, so it needs its own query.
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
        // addressOf(0) throws on a zero-length ByteArray; a zero-length Keychain item (only ever
        // externally created) must read as empty, not crash.
        if (len == 0) return ByteArray(0)
        return ByteArray(len).apply {
            usePinned {
                memcpy(it.addressOf(0), this@toByteArray.bytes, this@toByteArray.length)
            }
        }
    }
}

// The caller keeps ownership of [keySizeRef] and [privateKeyAttrs]; the attribute dictionary is
// created with null value-callbacks, so it retains neither.
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
