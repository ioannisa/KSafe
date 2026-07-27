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

/**
 * Custody of one web key: the non-extractable WebCrypto key in IndexedDB is sandbox protection.
 * Without `crypto.subtle` that key cannot exist and every decrypt fails, so persisted ciphertext
 * must not keep claiming it — report the degrade, matching `protectionInfo`.
 */
private fun webKeyTier(protection: KSafeProtection?): KSafeKeyTier = when {
    protection == null -> KSafeKeyTier.SOFTWARE
    !webCryptoSubtleAvailable() -> KSafeKeyTier.SOFTWARE
    else -> KSafeKeyTier.SANDBOX_PROTECTED
}

private fun buildWebKSafe(
    fileName: String?,
    lazyLoad: Boolean,
    config: KSafeConfig,
    securityPolicy: KSafeSecurityPolicy,
    plaintextCacheTtl: Duration,
    testEngine: KSafeEncryption?,
): KSafe {
    requireValidStoreFileName(fileName)
    validateSecurityPolicy(securityPolicy)

    // Prefix-free so no store's prefix string-prefixes another's, or startsWith()-scoped reads and
    // clearAll() of KSafe("user") would reach into KSafe("user_cache"). Old data migrates below.
    val legacyStoragePrefix: String = if (fileName != null) "ksafe_${fileName}_" else "ksafe_default_"

    // appNamespace must isolate the data namespace too: else same-origin setups sharing a fileName
    // collide on the same localStorage slots and overwrite each other with undecryptable ciphertext.
    // `@` delimits the segment — outside the fileName and sanitized appNamespace charsets — keeping
    // the scheme prefix-free and injective; canonicalNamespaceToken adds a collision digest when
    // the sanitization is lossy, so distinct configured ids can't share one prefix.
    val appNs: String? = canonicalNamespaceToken(config.appNamespace)
    val nsSegment: String = if (appNs != null) "$appNs@" else ""
    val storagePrefix: String = if (fileName != null) "ksafe.$nsSegment${fileName}:" else "ksafe.$nsSegment:"

    // The ≤ 2.2.1 lossy segment, when it differs from the canonical one: a shipped app's live
    // data sits under the old prefix, so it is carried forward (marker-gated, copy-if-absent,
    // source retained — a colliding sibling namespace may still need to migrate from it too).
    // Runs FIRST among the migrations: it was this app's ACTIVE prefix right up to the upgrade,
    // so it holds the newest data and must win the copy-if-absent over the older sources below.
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

    // KSafe() and KSafe("default") both map to `ksafe_default_`; their new prefixes differ but the
    // source is shared, so neither may delete it or the other loses its data.
    val legacyPrefixShared: Boolean = webSharesDefaultLegacyPrefix(fileName)

    // The old flat layout has no appNamespace segment, so it is one shared source for every
    // namespace of a fileName. When this is a unique, un-namespaced store we MOVE it (deleteSource),
    // so it can't re-seed; otherwise the source must be retained (a co-existing namespace or the
    // shared default may still need to migrate from it). Either way the copy-forward is gated
    // behind a one-time persistent marker, exactly like the pre-appNamespace carry-forward below:
    // even the MOVE leaves an entry at the source when its copy failed (quota) or its removal did,
    // and an ungated re-run copies that leftover back into a store the user has since wiped — the
    // wipe having freed the very space the copy needed. The marker lives OUTSIDE storagePrefix so
    // clearAll() can't erase it, and is set only once every copy verifiably succeeded — a partial
    // copy must retry on the next construction, not be sealed behind the marker with the values
    // stranded at the source. An explicit clear() seals the marker instead (see
    // markersSealedOnClear below): the user chose an empty store, so the retry is over.
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
    // Carry the pre-appNamespace prefix forward ONCE, gated on a persistent marker: the source is
    // never deleted, so without the gate copy-if-absent re-seeds the store on every construction,
    // resurrecting secrets a prior clearAll() wiped. The marker lives OUTSIDE storagePrefix so
    // clearAll() can't erase it, and is set only once every copy verifiably succeeded so a
    // partial copy retries on the next construction (see the legacy-prefix marker above).
    val migratedMarker = "ksafe.__nsmigrated__.$nsSegment${fileName ?: ""}"
    if (nsSegment.isNotEmpty()) {
        if (localStorageGet(migratedMarker) == null) {
            val unNamespaced = if (fileName != null) "ksafe.${fileName}:" else "ksafe.:"
            if (migrateLegacyLocalStoragePrefix(unNamespaced, storagePrefix, deleteSource = false)) {
                runCatching { localStorageSet(migratedMarker, "1") }
            }
        }
    }

    // The migrations above re-run while their done-marker is absent — including when the marker
    // WRITE failed after a successful copy. clear() therefore seals every marker that gates a
    // copy-forward into this store, so a wiped store can't be re-seeded from a source that
    // outlived the wipe (by design, or by a failure that stranded an entry at it).
    val markersSealedOnClear = buildList {
        if (nsSegment.isNotEmpty() && legacyLossyNs != null) add(lossyMigratedMarker)
        add(legacyMigratedMarker)
        if (nsSegment.isNotEmpty()) add(migratedMarker)
        // The engine's key records migrate forward on the same terms as the data, so the wipe
        // seals both. One marker then stands in for the per-alias deletion tombstone every later
        // delete would otherwise leave permanently in the shared origin quota.
        webKeyMigrationSealMarker(config.appNamespace, legacyStoragePrefix, fileName)?.let(::add)
    }

    // The engine keeps the legacy prefix: it namespaces the IndexedDB record names holding the
    // non-extractable keys, so changing it would orphan every key and make ciphertext undecryptable.
    val engine: KSafeEncryption =
        testEngine ?: WebSoftwareEncryption(config, legacyStoragePrefix, fileName)

    val core = KSafeCore(
        storeIdentity = fileName ?: "",
        keyNamespace = fileName,
        storage = LocalStorageStorage(storagePrefix, markersSealedOnClear),
        engineProvider = { engine },
        config = config,
        // Forced PLAIN_TEXT: WebCrypto can't decrypt from the sync getDirect path.
        memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
        plaintextCacheTtl = plaintextCacheTtl,
        // Strip requireUnlockedDevice: the strict read path routes to the engine's blocking decrypt,
        // which async-only WebCrypto can't serve, making strict values write-only. Clearing keeps them readable.
        modeTransformer = { mode ->
            if (mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice) {
                mode.copy(requireUnlockedDevice = false)
            } else {
                mode
            }
        },
        resolveKeyStorage = { _, protection, _ -> webKeyTier(protection).asKeyStorage() },
        resolveKeyLevel = { _, protection, _ -> webKeyTier(protection).asProtectionLevel() },
        lazyLoad = lazyLoad,
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
    // Without crypto.subtle every encrypted read/write fails; report effectiveLevel=SOFTWARE so
    // callers can preflight instead of trusting a fixed SANDBOX_PROTECTED.
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
        // Recomputed per access: crypto.subtle availability can vary with the page's security context.
        protectionInfoProvider = { if (webCryptoSubtleAvailable()) securedSnapshot else insecureSnapshot },
    )
}

/**
 * Suspends until the in-memory cache is fully loaded from localStorage, including async WebCrypto
 * decryption of every encrypted value. Call before `getDirect` / `mutableStateOf` / Compose
 * delegates for a deterministic first read; web-only (other targets preload synchronously).
 */
suspend fun KSafe.awaitCacheReady() = core.ensureCacheReadySuspend()
