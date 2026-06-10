package eu.anifantakis.lib.ksafe

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStoreFile
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.DataStoreDekStore
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

private val fileNameRegex = Regex("[a-z][a-z0-9_]*")

const val KEY_ALIAS_PREFIX: String = "eu.anifantakis.ksafe"

/**
 * Sentinel user-key segments for the per-datastore master keys created by the
 * v2 envelope. Reserved by the leading-`__` / trailing-`__` convention used
 * everywhere else in KSafe — collisions with real user keys are impossible.
 */
private const val MASTER_KEY_DEFAULT: String = "__ksafe_master__"
private const val MASTER_KEY_LOCKED: String = "__ksafe_master_locked__"

private val dataStoreCache = ConcurrentHashMap<String, DataStore<Preferences>>()

/**
 * The owning [CoroutineScope] per datastore path. Kept so that a `close()`-then-recreate
 * on the same file (common in tests and DI re-init) can await the prior owner's teardown:
 * DataStore only releases a file once that scope's [Job] completes, so awaiting it avoids
 * the "multiple DataStores active for the same file" guard.
 */
private val dataStoreScopes = ConcurrentHashMap<String, CoroutineScope>()

/**
 * Android factory for [KSafe]. Resolves to the same call syntax as the pre-2.0
 * `KSafe(context, ...)` constructor.
 *
 * Owns the Android-specific concerns: Context-backed DataStore creation
 * (cached per filename so repeated DI re-inits don't crash with
 * "multiple active instances"), StrongBox capability detection, and the
 * per-key [KSafeKeyStorage] tier reported by [getKeyInfo].
 *
 * @param context Android Context (typically the Application).
 * @param fileName Optional logical file name (lowercase letters / digits /
 *   underscores). Used to differentiate multiple [KSafe] instances in the same
 *   process. If null, the default datastore name is used.
 * @param lazyLoad Defer cache preload until first access.
 * @param memoryPolicy How decrypted values live in RAM (default
 *   [KSafeMemoryPolicy.LAZY_PLAIN_TEXT]).
 * @param config Cryptographic + JSON configuration.
 * @param securityPolicy Runtime security checks (root / debugger / etc.).
 * @param plaintextCacheTtl TTL for the
 *   [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE] policy.
 * @param useStrongBox Deprecated — use `KSafeProtection.HARDWARE_ISOLATED`
 *   per property instead.
 * @param baseDir Optional override for the directory in which the DataStore
 *   `.preferences_pb` file is stored. If null (default) KSafe uses the
 *   Context-managed app-private path
 *   (`/data/data/<package>/files/datastore/...`), which is the recommended
 *   choice — Android's app sandbox already enforces correct permissions there.
 *   If you supply a custom directory, KSafe will create it if missing but
 *   cannot enforce sandbox isolation; do **not** point it at external storage
 *   (SD card / `getExternalFilesDir()`) for sensitive data, where world-
 *   readable semantics may apply.
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
    if (fileName != null && !fileName.matches(fileNameRegex)) {
        throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores")
    }

    SecurityChecker.applicationContext = context.applicationContext

    validateSecurityPolicy(securityPolicy)

    val hasStrongBox: Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    val deviceKeyStorages: Set<KSafeKeyStorage> = buildSet {
        add(KSafeKeyStorage.HARDWARE_BACKED)
        if (hasStrongBox) add(KSafeKeyStorage.HARDWARE_ISOLATED)
    }

    val baseFileName = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" }
        ?: "eu_anifantakis_ksafe_datastore"

    // Resolve the actual DataStore file path. Cache by absolute path so that
    // (fileName, baseDir) pairs uniquely identify a DataStore — two callers
    // pointing at the same file share the same DataStore (avoiding DataStore's
    // "multiple active instances" error); two callers pointing at different
    // dirs get separate DataStores.
    val datastoreFile: File = if (baseDir != null) {
        if (!baseDir.exists()) baseDir.mkdirs()
        File(baseDir, "$baseFileName.preferences_pb")
    } else {
        context.preferencesDataStoreFile(baseFileName)
    }

    // DataStore launches its own coroutines on the scope it's given; we
    // hold one we control so close() can dispose it. The Android-only
    // process-static `dataStoreCache` exists to dedupe instances per
    // file path (DataStore refuses multiple active instances per file);
    // entries used to stay forever, so each test left both the cache
    // entry and its DataStore + scope pinned. We now evict the entry
    // and cancel the scope from `onCancel` below — but only if the
    // factory actually created a fresh entry on this call (otherwise
    // we'd close another caller's still-active DataStore).
    val datastorePath = datastoreFile.absolutePath
    var ownedScope: CoroutineScope? = null
    val dataStore: DataStore<Preferences> = dataStoreCache.getOrPut(datastorePath) {
        // A prior owner of this path may have just been closed: its scope is cancelling,
        // but DataStore releases the file only once that scope's Job fully completes.
        // Await it (bounded) before opening a new DataStore on the same file, so a
        // close()-then-recreate can't trip DataStore's "multiple DataStores active for
        // the same file" guard. No prior scope (the common case) → no wait.
        dataStoreScopes.remove(datastorePath)?.coroutineContext?.get(Job)?.let { priorJob ->
            runBlocking { withTimeoutOrNull(2_000) { priorJob.join() } }
        }
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        ownedScope = scope
        dataStoreScopes[datastorePath] = scope
        PreferenceDataStoreFactory.create(
            scope = scope,
            produceFile = { datastoreFile }
        )
    }

    // One storage instance shared by the engine (for its wrapped DEK) and the core, so
    // each safe's DEK lives in that safe's own DataStore — not in SharedPreferences.
    val storage = DataStoreStorage(dataStore)
    val engine: KSafeEncryption = testEngine
        ?: AndroidKeystoreEncryption(config = config, dekStore = DataStoreDekStore(storage))

    fun resolveKeyStorageTier(userKey: String, protection: KSafeProtection?): KSafeKeyStorage {
        if (protection == null) return KSafeKeyStorage.SOFTWARE
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasStrongBox)
            KSafeKeyStorage.HARDWARE_ISOLATED
        else KSafeKeyStorage.HARDWARE_BACKED
    }

    fun resolveKeyLevelTier(userKey: String, protection: KSafeProtection?): KSafeProtectionLevel {
        if (protection == null) return KSafeProtectionLevel.SOFTWARE
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasStrongBox)
            KSafeProtectionLevel.HARDWARE_ISOLATED
        else KSafeProtectionLevel.HARDWARE_BACKED
    }

    /**
     * Honors the deprecated `useStrongBox` constructor flag by promoting every
     * default-protection encrypted write to [KSafeEncryptedProtection.HARDWARE_ISOLATED].
     * Writes that explicitly request a protection level pass through unchanged.
     */
    @Suppress("DEPRECATION")
    fun promoteMode(mode: KSafeWriteMode): KSafeWriteMode {
        if (!useStrongBox) return mode
        if (mode !is KSafeWriteMode.Encrypted) return mode
        if (mode.protection != KSafeEncryptedProtection.DEFAULT) return mode
        return KSafeWriteMode.Encrypted(
            protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
            requireUnlockedDevice = mode.requireUnlockedDevice,
        )
    }

    val core = KSafeCore(
        storage = storage,
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = ::resolveKeyStorageTier,
        resolveKeyLevel = ::resolveKeyLevelTier,
        lazyLoad = lazyLoad,
        keyAlias = { userKey ->
            listOfNotNull(KEY_ALIAS_PREFIX, fileName, userKey).joinToString(".")
        },
        masterAlias = { requireUnlockedDevice ->
            val sentinel = if (requireUnlockedDevice) MASTER_KEY_LOCKED else MASTER_KEY_DEFAULT
            listOfNotNull(KEY_ALIAS_PREFIX, fileName, sentinel).joinToString(".")
        },
        modeTransformer = ::promoteMode,
        onCancel = {
            val scope = ownedScope
            if (scope != null) {
                dataStoreCache.remove(datastorePath)
                // Leave the (now cancelling) scope registered under the path so a later
                // recreate awaits its teardown before opening a new DataStore on the file.
                scope.cancel()
            }
        },
    )

    // Android custody can't change after construction (no runtime fallback
    // path on this platform), so the provider returns a captured snapshot.
    val protectionInfoSnapshot = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        effectiveLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        custody = if (hasStrongBox) {
            "Android Keystore (TEE; StrongBox available per-write; relaxed DEFAULT values use a TEE-wrapped AES key held in memory)"
        } else {
            "Android Keystore (TEE; relaxed DEFAULT values use a TEE-wrapped AES key held in memory)"
        },
        notes = buildList {
            if (!hasStrongBox) add("android_strongbox_absent")
            // Relaxed DEFAULT entries are decrypted in userspace via a data-encryption
            // key wrapped by the (non-exportable) TEE master key. The wrapped DEK is at
            // rest; the unwrapped DEK lives in process memory after first use — the same
            // posture as the Apple/JVM engines. HARDWARE_ISOLATED and the strict
            // requireUnlockedDevice master keep keys inside the TEE on every op.
            add("relaxed_default_uses_software_dek")
        },
    )
    return KSafe(
        core = core,
        deviceKeyStorages = deviceKeyStorages,
        protectionInfoProvider = { protectionInfoSnapshot },
    )
}
