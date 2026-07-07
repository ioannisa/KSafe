package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.LocalStorageStorage
import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.migrateLegacyLocalStoragePrefix
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun encodeBase64Web(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64Web(encoded: String): ByteArray = Base64.decode(encoded)

private val fileNameRegex = Regex("[a-z][a-z0-9_]*")

/** Per-datastore master-key alias; web has no device-lock, so locked/unlocked collapse to one. */
private const val MASTER_KEY_DEFAULT: String = "__ksafe_master__"

/**
 * Web (wasmJs + js) factory for [KSafe].
 *
 * WebCrypto is async-only, so the memory policy is effectively PLAIN_TEXT (the `memoryPolicy`
 * argument is accepted for parity but ignored): encrypted values are decrypted during the
 * background preload and cached as plaintext, since the non-suspend [getDirect] path can't
 * decrypt on demand. A `getDirect` that races the preload returns `defaultValue` until it
 * completes; call [awaitCacheReady] first for a deterministic first read.
 */
@Suppress("UNUSED_PARAMETER")
fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
): KSafe = buildWebKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    testEngine = null,
)

@Suppress("UNUSED_PARAMETER")
@PublishedApi
internal fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    testEngine: KSafeEncryption,
): KSafe = buildWebKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    testEngine = testEngine,
)

private fun buildWebKSafe(
    fileName: String?,
    lazyLoad: Boolean,
    config: KSafeConfig,
    securityPolicy: KSafeSecurityPolicy,
    plaintextCacheTtl: Duration,
    testEngine: KSafeEncryption?,
): KSafe {
    if (fileName != null && !fileName.matches(fileNameRegex)) {
        throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores")
    }
    validateSecurityPolicy(securityPolicy)

    // Prefix-free data namespace: `.` and `:` can't appear in a fileName ([a-z][a-z0-9_]*), so no
    // store's prefix can string-prefix another's — else startsWith()-scoped reads and clearAll() of
    // KSafe("user") would reach into KSafe("user_cache"). Old `ksafe_<name>_` data migrates below.
    val legacyStoragePrefix: String = if (fileName != null) "ksafe_${fileName}_" else "ksafe_default_"

    // appNamespace isolates the data namespace too, not just the engine's IndexedDB key record:
    // without it, two same-origin setups with the same fileName but different appNamespace collide
    // on the same localStorage slots and overwrite each other with undecryptable ciphertext. `@`
    // delimits the segment — outside both the fileName alphabet and the sanitized appNamespace
    // charset ([A-Za-z0-9._-]) — so the scheme stays prefix-free and injective.
    val appNs: String? = config.appNamespace?.trim()?.takeIf { it.isNotEmpty() }
        ?.replace(Regex("[^A-Za-z0-9._-]"), "_")?.take(120)?.takeIf { it.isNotEmpty() }
    val nsSegment: String = if (appNs != null) "$appNs@" else ""
    val storagePrefix: String = if (fileName != null) "ksafe.$nsSegment${fileName}:" else "ksafe.$nsSegment:"

    // `ksafe_default_` is shared by two valid constructions: KSafe() (unnamed) and
    // KSafe(fileName = "default") both map to it. Their new prefixes differ (`ksafe.:` vs
    // `ksafe.default:`) but the migration source is the same data, so neither may delete it or the
    // other loses its data.
    val legacyPrefixShared: Boolean = fileName == null || fileName == "default"

    // Carry the old flat `ksafe_<name>_` layout forward. It has no appNamespace segment — one
    // shared source for every namespace of a fileName — so delete it only for a unique legacy
    // prefix with no appNamespace. With namespaces active, or for the shared `ksafe_default_`,
    // copy-if-absent and leave the source so every valid construction migrates from it instead of
    // the first-constructed one destroying it for the others.
    migrateLegacyLocalStoragePrefix(
        legacyStoragePrefix,
        storagePrefix,
        deleteSource = nsSegment.isEmpty() && !legacyPrefixShared,
    )
    // When an appNamespace is set, also carry forward the un-namespaced `ksafe.<name>:` prefix
    // written before appNamespace isolated the data store.
    if (nsSegment.isNotEmpty()) {
        val unNamespaced = if (fileName != null) "ksafe.${fileName}:" else "ksafe.:"
        // Non-destructive: the un-namespaced prefix is also the live prefix of a co-existing
        // no-namespace store on the same fileName, and this runs on every construction (no
        // done-marker), so deleting the source would cannibalize that sibling's writes. The
        // namespaced store scopes its reads/clear to its own prefix, so the copy never bleeds.
        migrateLegacyLocalStoragePrefix(unNamespaced, storagePrefix, deleteSource = false)
    }

    // The engine deliberately keeps the legacy prefix: it namespaces the IndexedDB record names
    // holding the non-extractable keys, so changing it would orphan every key and make existing
    // ciphertext undecryptable. Key records are addressed by exact name (no startsWith scans), so
    // the prefix-free property isn't needed here.
    val engine: KSafeEncryption =
        testEngine ?: WebSoftwareEncryption(config, legacyStoragePrefix)

    val core = KSafeCore(
        storage = LocalStorageStorage(storagePrefix),
        engineProvider = { engine },
        config = config,
        // Forced PLAIN_TEXT: WebCrypto can't decrypt from the sync getDirect path, so the cache
        // holds plaintext after preload. A user-supplied value is ignored.
        memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
        plaintextCacheTtl = plaintextCacheTtl,
        // Strip requireUnlockedDevice on web: a browser has no device-lock, and the strict read
        // path routes to the engine's blocking decrypt, which the async-only WebCrypto engine
        // can't serve — making strict values write-only. Clearing the flag keeps them readable.
        modeTransformer = { mode ->
            if (mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice) {
                mode.copy(requireUnlockedDevice = false)
            } else {
                mode
            }
        },
        resolveKeyStorage = { _, _ -> KSafeKeyStorage.SOFTWARE },
        resolveKeyLevel = { _, protection ->
            // Encrypted values use a non-extractable CryptoKey bound to the origin: SANDBOX_PROTECTED.
            if (protection == null) KSafeProtectionLevel.SOFTWARE
            else KSafeProtectionLevel.SANDBOX_PROTECTED
        },
        lazyLoad = lazyLoad,
        keyAlias = { userKey -> fileName?.let { "$it:$userKey" } ?: userKey },
        masterAlias = { _ -> fileName?.let { "$it:$MASTER_KEY_DEFAULT" } ?: MASTER_KEY_DEFAULT },
    )

    // Web custody can't change after construction, so the provider
    // returns a captured snapshot.
    val protectionInfoSnapshot = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.SANDBOX_PROTECTED,
        effectiveLevel = KSafeProtectionLevel.SANDBOX_PROTECTED,
        custody = "WebCrypto non-extractable key in IndexedDB",
        notes = emptyList(),
    )
    return KSafe(
        core = core,
        deviceKeyStorages = setOf(KSafeKeyStorage.SOFTWARE),
        protectionInfoProvider = { protectionInfoSnapshot },
    )
}

/**
 * Suspends until the in-memory cache is fully loaded from localStorage, including async WebCrypto
 * decryption of every encrypted value. Call before `getDirect` / `mutableStateOf` / Compose
 * delegates for a deterministic first read; web-only (other targets preload synchronously).
 */
suspend fun KSafe.awaitCacheReady() = core.ensureCacheReadySuspend()
