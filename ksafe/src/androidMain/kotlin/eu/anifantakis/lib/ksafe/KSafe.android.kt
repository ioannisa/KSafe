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

/**
 * Per-datastore-path shared backend. Co-existing [KSafe] instances on the same file share
 * ONE backend, so they share one [DataStore] **and** one [AndroidKeystoreEncryption] engine
 * — i.e. one in-memory DEK cache and one per-alias lock map over the single persisted
 * wrapped-DEK slot. Creating a fresh engine per instance (the old behaviour) let those DEK
 * caches diverge from the one on-disk slot, silently and permanently losing data after a
 * `clearAll()` on one instance or a concurrent first-write race across two (deep-review
 * #7 / #46).
 *
 * The backend is **ref-counted**: its scope is cancelled and the entry evicted only when
 * the *last* instance on the path closes, so closing one instance can't cancel the
 * DataStore out from under another live one (deep-review #50). All creation / acquisition /
 * release for a given path is serialized by [pathLock], which also makes creation atomic —
 * a non-atomic `getOrPut` could open two DataStores for one file (DataStore then throws
 * "multiple DataStores active for the same file"; deep-review #27 / #49).
 */
private class AndroidBackend(
    val dataStore: DataStore<Preferences>,
    val scope: CoroutineScope,
) {
    /** Live [KSafe] instances sharing this backend. Evicted when it hits 0. */
    val refCount = java.util.concurrent.atomic.AtomicInteger(0)

    /** The single shared engine, created lazily on first production use (never for tests). */
    @Volatile
    var engine: AndroidKeystoreEncryption? = null

    fun engineOrCreate(create: () -> AndroidKeystoreEncryption): AndroidKeystoreEncryption {
        engine?.let { return it }
        return synchronized(this) { engine ?: create().also { engine = it } }
    }
}

/** Live backends keyed by absolute datastore path. Structurally safe across paths
 *  (ConcurrentHashMap); the check-then-act for a single path is serialized by [pathLock]. */
private val backends = ConcurrentHashMap<String, AndroidBackend>()

/**
 * Scope of the most-recently-evicted backend per path, awaited (bounded) before a recreate
 * opens a new DataStore on the same file: DataStore frees a file only once its scope's [Job]
 * completes, so awaiting it avoids the "multiple DataStores active for the same file" guard.
 */
private val terminatingScopes = ConcurrentHashMap<String, CoroutineScope>()

/** One monitor per datastore path — serializes acquire/release (and the prior-scope await)
 *  so a single file never has two DataStores constructed concurrently. */
private val pathLocks = ConcurrentHashMap<String, Any>()
private fun pathLock(path: String): Any = pathLocks.computeIfAbsent(path) { Any() }

/**
 * Returns the shared backend for [path], creating it (atomically, per path) on first use
 * and incrementing its ref-count. A recreate after the previous owner closed awaits that
 * owner's teardown first (bounded), since DataStore releases the file only once its scope
 * completes.
 */
private fun acquireBackend(
    path: String,
    createDataStore: (CoroutineScope) -> DataStore<Preferences>,
): AndroidBackend = synchronized(pathLock(path)) {
    backends[path]?.let {
        it.refCount.incrementAndGet()
        return it
    }
    terminatingScopes.remove(path)?.coroutineContext?.get(Job)?.let { priorJob ->
        runBlocking { withTimeoutOrNull(2_000) { priorJob.join() } }
    }
    val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    val backend = AndroidBackend(createDataStore(scope), scope).also { it.refCount.set(1) }
    backends[path] = backend
    backend
}

/**
 * Drops one ref to the backend for [path]; when the last instance releases, evicts the
 * entry, parks the scope for the next recreate to await, and cancels it. Idempotency is the
 * caller's responsibility (each [KSafe] releases exactly once via an [java.util.concurrent.atomic.AtomicBoolean]).
 */
private fun releaseBackend(path: String) = synchronized(pathLock(path)) {
    val backend = backends[path] ?: return
    if (backend.refCount.decrementAndGet() <= 0) {
        backends.remove(path)
        terminatingScopes[path] = backend.scope
        backend.scope.cancel()
    }
}

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

    // Acquire the per-path shared backend (DataStore + scope + engine), ref-counted so
    // that co-existing instances on the same file share one DataStore AND one engine, and
    // only the last to close tears the scope down. Creation is atomic per path. See
    // [AndroidBackend] / [acquireBackend].
    val datastorePath = datastoreFile.absolutePath
    val backend = acquireBackend(datastorePath) { scope ->
        PreferenceDataStoreFactory.create(
            // Quarantine a corrupt .preferences_pb and continue from an empty store instead of
            // throwing CorruptionException on every read forever — which crashes the background
            // collector and makes getDirect silently return defaults (deep-review #23). The
            // corrupt bytes are copied aside for recovery.
            corruptionHandler = ReplaceFileCorruptionHandler {
                runCatching {
                    datastoreFile.copyTo(
                        File(datastoreFile.parentFile, "${datastoreFile.name}.corrupt-${System.currentTimeMillis()}"),
                        overwrite = false,
                    )
                }
                emptyPreferences()
            },
            scope = scope,
            produceFile = { datastoreFile },
        )
    }

    // One storage instance shared by the engine (for its wrapped DEK) and the core, so
    // each safe's DEK lives in that safe's own DataStore — not in SharedPreferences. The
    // shared production engine is created lazily on the backend (never for tests), so all
    // instances on this file share one DEK cache / lock map over the single wrapped-DEK slot.
    val storage = DataStoreStorage(backend.dataStore)
    val engine: KSafeEncryption = testEngine
        ?: backend.engineOrCreate {
            AndroidKeystoreEncryption(config = config, dekStore = DataStoreDekStore(storage))
        }

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

    // Guards this instance's single backend release (KSafeCore.cancel() is idempotent).
    val released = java.util.concurrent.atomic.AtomicBoolean(false)

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
            // Drop this instance's ref to the shared backend. Only the last instance on
            // the path actually cancels the scope + evicts the entry (ref-counted), so
            // closing one instance can't cancel the DataStore out from under another live
            // one. KSafeCore.cancel() is idempotent and may call this more than once, so
            // guard the release to exactly one decrement per instance.
            if (released.compareAndSet(false, true)) releaseBackend(datastorePath)
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
