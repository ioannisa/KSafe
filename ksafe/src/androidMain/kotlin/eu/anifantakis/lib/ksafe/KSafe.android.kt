package eu.anifantakis.lib.ksafe

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.preferencesDataStoreFile
import eu.anifantakis.lib.ksafe.internal.ANDROID_KEYSTORE_PROVIDER
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.BACKEND_TEARDOWN_TIMEOUT_MS
import eu.anifantakis.lib.ksafe.internal.DATASTORE_FILE_SUFFIX
import eu.anifantakis.lib.ksafe.internal.DataStoreDekStore
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KSAFE_OS_STORE_IDENTITY
import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeKeyTier
import eu.anifantakis.lib.ksafe.internal.KSafeProtectionNotes
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.SharedBackendRegistry
import eu.anifantakis.lib.ksafe.internal.SharedStoreBackend
import eu.anifantakis.lib.ksafe.internal.asKeyStorage
import eu.anifantakis.lib.ksafe.internal.asProtectionLevel
import eu.anifantakis.lib.ksafe.internal.dataStoreBaseFileName
import eu.anifantakis.lib.ksafe.internal.promoteDefaultToIsolated
import eu.anifantakis.lib.ksafe.internal.quarantineCorruptStoreFile
import eu.anifantakis.lib.ksafe.internal.requireValidStoreFileName
import eu.anifantakis.lib.ksafe.internal.resolveStoreIdentity
import eu.anifantakis.lib.ksafe.internal.sweepCorruptQuarantineCopies
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

const val KEY_ALIAS_PREFIX: String = KSAFE_OS_STORE_IDENTITY

/**
 * Per-datastore-path shared backend: every [KSafe] on one file shares a single [DataStore]
 * and [AndroidKeystoreEncryption] engine, so their in-memory DEK caches can't diverge from
 * the one on-disk wrapped-DEK slot (which would silently lose data).
 */
private class AndroidBackend(
    val dataStore: DataStore<Preferences>,
    val storage: KSafePlatformStorage,
    scope: CoroutineScope,
) : SharedStoreBackend(scope)

private val backends = SharedBackendRegistry<AndroidBackend>(Dispatchers.IO) { path ->
    println(
        "KSafe: prior DataStore for '$path' had not finished tearing down within " +
            "${BACKEND_TEARDOWN_TIMEOUT_MS}ms; the first access may transiently fail " +
            "(\"multiple DataStores active for the same file\") until it does, then self-recovers."
    )
}

// Actual-custody probe results per alias. Safe to cache: a minted Keystore key never migrates
// between security levels in place — rotation and self-heal mint under NEW aliases.
private val strongBoxByAlias = ConcurrentHashMap<String, Boolean>()

/**
 * Whether the Keystore key at [alias] actually resides in StrongBox — key creation can silently
 * fall back to the TEE ([android.security.keystore.StrongBoxUnavailableException]) or reuse a
 * pre-existing TEE key, so the requested tier alone can over-report. Only answerable on API 31+
 * (`KeyInfo.getSecurityLevel`; below that KeyInfo cannot tell StrongBox from TEE); `null` means
 * indeterminate (older API, absent alias, probe failure) and callers keep the documented
 * capability inference.
 */
private fun isKeyActuallyStrongBox(alias: String?): Boolean? {
    if (alias == null || Build.VERSION.SDK_INT < 31) return null
    strongBoxByAlias[alias]?.let { return it }
    return try {
        val keyStore = java.security.KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
        val key = keyStore.getKey(alias, null) as? javax.crypto.SecretKey ?: return null
        val info = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE_PROVIDER)
            .getKeySpec(key, android.security.keystore.KeyInfo::class.java)
            as android.security.keystore.KeyInfo
        val strongBox =
            info.securityLevel == android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX
        strongBoxByAlias[alias] = strongBox
        strongBox
    } catch (_: Throwable) {
        null
    }
}

/**
 * Android factory for [KSafe]; same call syntax as the pre-2.0 `KSafe(context, ...)` constructor.
 *
 * @param fileName Optional logical name (lowercase letters / digits / underscores) that
 *   differentiates instances in one process; null uses the default datastore name.
 *   **[fileName] is the key-isolation boundary on Android**: the Android Keystore is a single
 *   per-app store keyed by alias string, and KSafe's key aliases are scoped by [fileName]
 *   only (not [baseDir]). Two instances that must have INDEPENDENT keys and lifecycles must
 *   therefore use DISTINCT [fileName]s — two instances sharing a [fileName] but differing only
 *   in [baseDir] share the same Keystore key material, so one instance's `clearAll()` deletes
 *   the key the other still needs. (Their ciphertexts are still cryptographically isolated
 *   after a `rotateKeys()` via the v3 AAD, which binds the full store path.)
 * @param useStrongBox Deprecated — use `KSafeProtection.HARDWARE_ISOLATED` per property.
 * @param baseDir Optional override for the `.preferences_pb` directory. Null (recommended)
 *   uses the app-private path, where the sandbox enforces permissions. A custom dir is
 *   created if missing but not sandbox-isolated — never point it at external storage
 *   (SD card / `getExternalFilesDir()`) for sensitive data. Does NOT isolate key material —
 *   see [fileName].
 */
fun KSafe(
    context: Context,
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    @Suppress("DEPRECATION") useStrongBox: Boolean = false,
    baseDir: File? = null,
): KSafe = buildAndroidKSafe(
    context = context,
    fileName = fileName,
    lazyLoad = lazyLoad,
    memoryPolicy = memoryPolicy,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    useStrongBox = useStrongBox,
    baseDir = baseDir,
    testEngine = null,
)

@PublishedApi
internal fun KSafe(
    context: Context,
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    @Suppress("DEPRECATION") useStrongBox: Boolean = false,
    baseDir: File? = null,
    testEngine: KSafeEncryption,
): KSafe = buildAndroidKSafe(
    context = context,
    fileName = fileName,
    lazyLoad = lazyLoad,
    memoryPolicy = memoryPolicy,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    useStrongBox = useStrongBox,
    baseDir = baseDir,
    testEngine = testEngine,
)

private fun buildAndroidKSafe(
    context: Context,
    fileName: String?,
    lazyLoad: Boolean,
    memoryPolicy: KSafeMemoryPolicy,
    config: KSafeConfig,
    securityPolicy: KSafeSecurityPolicy,
    plaintextCacheTtl: Duration,
    useStrongBox: Boolean,
    baseDir: File?,
    testEngine: KSafeEncryption?,
): KSafe {
    requireValidStoreFileName(fileName)

    SecurityChecker.applicationContext = context.applicationContext

    validateSecurityPolicy(securityPolicy)

    val hasStrongBox: Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    val deviceKeyStorages: Set<KSafeKeyStorage> = buildSet {
        add(KSafeKeyStorage.HARDWARE_BACKED)
        if (hasStrongBox) add(KSafeKeyStorage.HARDWARE_ISOLATED)
    }

    val baseFileName = dataStoreBaseFileName(fileName)

    // Absolute path uniquely identifies a DataStore: same file → shared DataStore (avoids
    // DataStore's "multiple active instances" error), different dir → separate DataStores.
    val datastoreFile: File = if (baseDir != null) {
        if (!baseDir.exists()) baseDir.mkdirs()
        File(baseDir, "$baseFileName$DATASTORE_FILE_SUFFIX")
    } else {
        context.preferencesDataStoreFile(baseFileName)
    }

    val datastorePath = datastoreFile.absolutePath
    // Canonical spelling so a custom baseDir reached via a relative/symlinked/`..` path keeps one
    // identity; also the registry key, so two spellings of one file share one DataStore.
    val backendKey = runCatching { datastoreFile.canonicalPath }.getOrDefault(datastorePath)
    val rawDataDir = context.applicationInfo.dataDir
    // Home-relative v3 AAD identity, never the raw absolute path: moving the app to
    // adoptable storage relocates its data dir (/data/user/0/<pkg> → /mnt/expand/<uuid>/…)
    // while the AndroidKeyStore keys survive, so an absolute path would fail every rotated
    // entry's AAD after the move and the orphan sweep would then delete it. A custom baseDir
    // outside the data dir stays absolute (stableStoreIdentity's pass-through branch).
    val storeIdentity = resolveStoreIdentity(
        canonicalPath = backendKey,
        // /data/user/0/<pkg> is a symlink to /data/data/<pkg>, so a canonical path compared against
        // the raw dataDir would never prefix-match and the identity would silently stay absolute.
        canonicalHome = runCatching { File(rawDataDir).canonicalPath }.getOrDefault(rawDataDir),
        rawPath = datastorePath,
        rawHome = rawDataDir,
    )
    val backend = backends.acquire(backendKey) { scope ->
        val dataStore = PreferenceDataStoreFactory.create(
            // Quarantine a corrupt .preferences_pb and continue from empty, rather than throwing on
            // every read forever (which crashes the collector).
            corruptionHandler = ReplaceFileCorruptionHandler {
                quarantineCorruptStoreFile(datastoreFile)
                emptyPreferences()
            },
            scope = scope,
            produceFile = { datastoreFile },
        )
        // Per file, not per instance: its commit relay must reach every sibling's collector.
        AndroidBackend(dataStore, DataStoreStorage(dataStore), scope)
    }

    // The base alias (un-suffixed relaxed master — the only alias that used the DEK before key
    // rotation existed) MUST match masterAlias(false) below, so its record stays on the historical
    // fixed key and existing installs upgrade with zero migration.
    val storage = backend.storage
    val relaxedMasterBaseAlias = KSafeAliasFormat.dotted(fileName, KSafeReservedKeys.MASTER)
    val engine: KSafeEncryption = testEngine
        ?: backend.engineOrCreate {
            AndroidKeystoreEncryption(
                config = config,
                dekStore = DataStoreDekStore(storage, baseAlias = relaxedMasterBaseAlias),
            )
        }

    // A `false` probe means the alias's key VERIFIABLY sits in the TEE (silent StrongBox
    // fallback, or a tier-upgrade write reusing a pre-existing TEE key) — report the honest
    // tier. `true`/`null` keep the capability inference the KDoc documents.
    fun resolveKeyTier(protection: KSafeProtection?, engineAlias: String?): KSafeKeyTier {
        if (protection == null) return KSafeKeyTier.SOFTWARE
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasStrongBox &&
            isKeyActuallyStrongBox(engineAlias) != false
        ) KSafeKeyTier.HARDWARE_ISOLATED
        else KSafeKeyTier.HARDWARE_BACKED
    }

    // Guards this instance to exactly one backend release (KSafeCore.cancel() is idempotent).
    val released = java.util.concurrent.atomic.AtomicBoolean(false)

    val core = KSafeCore(
        // v3 AAD binds the FULL store path (baseDir + fileName), not just fileName: two instances
        // sharing a fileName but differing in baseDir share key material (the alias is fileName-
        // scoped — see factory KDoc), so the path binding cryptographically isolates their
        // ciphertexts after rotation. The KEK alias stays fileName-scoped: a non-exportable
        // Keystore key cannot move to a new alias without unrecoverable data loss.
        storeIdentity = storeIdentity.canonical,
        fallbackStoreIdentity = storeIdentity.fallback,
        keyNamespace = fileName,
        commitMutex = backend.commitMutex,
        storage = storage,
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = { _, protection, engineAlias -> resolveKeyTier(protection, engineAlias).asKeyStorage() },
        resolveKeyLevel = { _, protection, engineAlias -> resolveKeyTier(protection, engineAlias).asProtectionLevel() },
        lazyLoad = lazyLoad,
        keyAlias = { userKey -> KSafeAliasFormat.dotted(fileName, userKey) },
        masterAlias = { requireUnlockedDevice -> KSafeAliasFormat.dottedMaster(fileName, requireUnlockedDevice) },
        modeTransformer = { promoteDefaultToIsolated(it, useStrongBox) },
        onCancel = {
            if (released.compareAndSet(false, true)) backends.release(backendKey)
        },
    )
    core.attachSiblings(backend.siblings)

    val protectionInfoSnapshot = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        effectiveLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        custody = if (hasStrongBox) {
            "Android Keystore (TEE; StrongBox available per-write; relaxed DEFAULT values use a TEE-wrapped AES key held in memory)"
        } else {
            "Android Keystore (TEE; relaxed DEFAULT values use a TEE-wrapped AES key held in memory)"
        },
        notes = buildList {
            if (!hasStrongBox) add(KSafeProtectionNotes.ANDROID_STRONGBOX_ABSENT)
            // Relaxed DEFAULT values use a TEE-wrapped DEK whose unwrapped bytes live in process
            // memory after first use; HARDWARE_ISOLATED and strict masters keep keys in the TEE.
            add(KSafeProtectionNotes.ANDROID_RELAXED_DEFAULT_USES_SOFTWARE_DEK)
        },
    )
    return KSafe(
        core = core,
        deviceKeyStorages = deviceKeyStorages,
        protectionInfoProvider = { protectionInfoSnapshot },
        onClearAllCleanup = {
            // The quarantine copies also hold the wrapped DEK, not just ciphertext.
            sweepCorruptQuarantineCopies(datastoreFile)
        },
    )
}
