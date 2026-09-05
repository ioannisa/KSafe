package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeKeyTier
import eu.anifantakis.lib.ksafe.internal.KSafeProtectionNotes
import eu.anifantakis.lib.ksafe.internal.LocalStorageStorage
import eu.anifantakis.lib.ksafe.internal.WebSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.asKeyStorage
import eu.anifantakis.lib.ksafe.internal.asProtectionLevel
import eu.anifantakis.lib.ksafe.internal.canonicalNamespaceToken
import eu.anifantakis.lib.ksafe.internal.legacyLossyWebNamespaceToken
import eu.anifantakis.lib.ksafe.internal.localStorageGet
import eu.anifantakis.lib.ksafe.internal.localStorageSet
import eu.anifantakis.lib.ksafe.internal.migrateLegacyLocalStoragePrefix
import eu.anifantakis.lib.ksafe.internal.requireValidStoreFileName
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import eu.anifantakis.lib.ksafe.internal.webCryptoSubtleAvailable
import eu.anifantakis.lib.ksafe.internal.webKeyMigrationSealMarker
import eu.anifantakis.lib.ksafe.internal.webSharesDefaultLegacyPrefix
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Web (wasmJs + js) factory for [KSafe].
 *
 * WebCrypto is async-only, so `memoryPolicy` and `lazyLoad` are ignored: values are decrypted in a
 * background preload and cached as plaintext. A `getDirect` racing that preload returns
 * `defaultValue` — call [awaitCacheReady] first for a deterministic first read.
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
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    testEngine = testEngine,
)

/** Without `crypto.subtle` the non-extractable IndexedDB key cannot exist and every decrypt fails. */
private fun webKeyTier(protection: KSafeProtection?): KSafeKeyTier = when {
    protection == null -> KSafeKeyTier.SOFTWARE
    !webCryptoSubtleAvailable() -> KSafeKeyTier.SOFTWARE
    else -> KSafeKeyTier.SANDBOX_PROTECTED
}

private fun buildWebKSafe(
    fileName: String?,
    config: KSafeConfig,
    securityPolicy: KSafeSecurityPolicy,
    plaintextCacheTtl: Duration,
    testEngine: KSafeEncryption?,
): KSafe {
    requireValidStoreFileName(fileName)
    validateSecurityPolicy(securityPolicy)

    // Prefix-free, or clearAll() of KSafe("user") reaches into KSafe("user_cache").
    val legacyStoragePrefix: String = if (fileName != null) "ksafe_${fileName}_" else "ksafe_default_"

    // appNamespace must isolate the data namespace too, or same-origin stores sharing a fileName
    // overwrite each other. `@` is outside both charsets, keeping the scheme prefix-free.
    val appNs: String? = canonicalNamespaceToken(config.appNamespace)
    val nsSegment: String = if (appNs != null) "$appNs@" else ""
    val storagePrefix: String = if (fileName != null) "ksafe.$nsSegment${fileName}:" else "ksafe.$nsSegment:"

    // The older lossy segment. Runs FIRST: it was the ACTIVE prefix until the upgrade, so it holds
    // the newest data. Source retained — a colliding sibling namespace may still need it.
    val legacyLossyNs: String? = legacyLossyWebNamespaceToken(config.appNamespace)?.takeIf { it != appNs }
    val lossyMigratedMarker = "ksafe.__nslossymigrated__.$nsSegment${fileName ?: ""}"
    if (nsSegment.isNotEmpty() && legacyLossyNs != null) {
        if (localStorageGet(lossyMigratedMarker) == null) {
            val oldPrefix = if (fileName != null) "ksafe.$legacyLossyNs@${fileName}:" else "ksafe.$legacyLossyNs@:"
            if (migrateLegacyLocalStoragePrefix(oldPrefix, storagePrefix, deleteSource = false)) {
                runCatching { localStorageSet(lossyMigratedMarker, "1") }
            }
        }
    }

    // KSafe() and KSafe("default") share `ksafe_default_`, so neither may delete it.
    val legacyPrefixShared: Boolean = webSharesDefaultLegacyPrefix(fileName)

    // The flat layout has no namespace segment, so it is a shared source: MOVE it only when this
    // store owns it alone. Marker-gated either way, or a re-run copies a stranded entry back into
    // a store the user has since wiped; the marker sits outside storagePrefix, beyond clearAll().
    val legacyMigratedMarker = "ksafe.__legacymigrated__.$nsSegment${fileName ?: ""}"
    if (localStorageGet(legacyMigratedMarker) == null) {
        val ownsLegacyPrefixAlone = nsSegment.isEmpty() && !legacyPrefixShared
        if (migrateLegacyLocalStoragePrefix(
                legacyStoragePrefix, storagePrefix, deleteSource = ownsLegacyPrefixAlone,
            )
        ) {
            runCatching { localStorageSet(legacyMigratedMarker, "1") }
        }
    }
    // This source is never deleted: ungated, the copy re-seeds secrets a clearAll() wiped.
    val migratedMarker = "ksafe.__nsmigrated__.$nsSegment${fileName ?: ""}"
    if (nsSegment.isNotEmpty()) {
        if (localStorageGet(migratedMarker) == null) {
            val unNamespaced = if (fileName != null) "ksafe.${fileName}:" else "ksafe.:"
            if (migrateLegacyLocalStoragePrefix(unNamespaced, storagePrefix, deleteSource = false)) {
                runCatching { localStorageSet(migratedMarker, "1") }
            }
        }
    }

    // A migration re-runs while its marker is absent, so clear() seals them all.
    val markersSealedOnClear = buildList {
        if (nsSegment.isNotEmpty() && legacyLossyNs != null) add(lossyMigratedMarker)
        add(legacyMigratedMarker)
        if (nsSegment.isNotEmpty()) add(migratedMarker)
        // Key records migrate on the same terms as the data, so the wipe seals both.
        webKeyMigrationSealMarker(config.appNamespace, legacyStoragePrefix, fileName)?.let(::add)
    }

    // The engine keeps the legacy prefix: it names the IndexedDB key records, so changing it
    // orphans every key.
    val engine: KSafeEncryption =
        testEngine ?: WebSoftwareEncryption(config, legacyStoragePrefix, fileName)

    val core = KSafeCore(
        storeIdentity = fileName ?: "",
        keyNamespace = fileName,
        storage = LocalStorageStorage(storagePrefix, markersSealedOnClear),
        engineProvider = { engine },
        config = config,
        memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
        plaintextCacheTtl = plaintextCacheTtl,
        // Strict reads route to a blocking decrypt WebCrypto can't serve; clearing keeps them readable.
        modeTransformer = { mode ->
            if (mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice) {
                mode.copy(requireUnlockedDevice = false)
            } else {
                mode
            }
        },
        resolveKeyStorage = { _, protection, _ -> webKeyTier(protection).asKeyStorage() },
        resolveKeyLevel = { _, protection, _ -> webKeyTier(protection).asProtectionLevel() },
        // No runBlocking on web: without the collector, non-suspend reads serve defaults all session.
        lazyLoad = false,
        keyAlias = { userKey -> KSafeAliasFormat.colon(fileName, userKey) },
        // Web has no device lock, so both access policies route to the one master.
        masterAlias = { _ -> KSafeAliasFormat.colonMaster(fileName) },
    )

    val securedSnapshot = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.SANDBOX_PROTECTED,
        effectiveLevel = KSafeProtectionLevel.SANDBOX_PROTECTED,
        custody = "WebCrypto non-extractable key in IndexedDB",
        notes = emptyList(),
    )
    val insecureSnapshot = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.SANDBOX_PROTECTED,
        effectiveLevel = KSafeProtectionLevel.SOFTWARE,
        custody = "WebCrypto (crypto.subtle) unavailable — not a secure context; encrypted " +
            "reads/writes will fail. Serve over HTTPS or from a localhost origin.",
        notes = listOf(KSafeProtectionNotes.WEB_CRYPTO_SUBTLE_UNAVAILABLE),
    )
    return KSafe(
        core = core,
        deviceKeyStorages = setOf(KSafeKeyStorage.SOFTWARE),
        // Recomputed per access: crypto.subtle availability varies with the page's security context.
        protectionInfoProvider = { if (webCryptoSubtleAvailable()) securedSnapshot else insecureSnapshot },
    )
}

/** Suspends until the cache is loaded from localStorage, decrypting every encrypted value. Call
 *  before `getDirect` or a Compose delegate for a deterministic first read. */
suspend fun KSafe.awaitCacheReady() = core.ensureCacheReadySuspend()
