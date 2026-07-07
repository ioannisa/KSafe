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

// Reserved master-key segments; the `__`-fenced convention can't collide with a user key.
private const val MASTER_KEY_DEFAULT: String = "__ksafe_master__"
private const val MASTER_KEY_LOCKED: String = "__ksafe_master_locked__"

/**
 * Per-datastore-path shared backend: every [KSafe] on one file shares a single [DataStore]
 * and [AndroidKeystoreEncryption] engine, so their in-memory DEK caches can't diverge from
 * the one on-disk wrapped-DEK slot (which would silently lose data). Ref-counted — only the
 * last instance to close tears down the scope; [pathLock] serializes acquire/release and
 * keeps creation atomic (two DataStores on one file throw "multiple DataStores active").
 */
private class AndroidBackend(
    val dataStore: DataStore<Preferences>,
    val scope: CoroutineScope,
) {
    /** Live [KSafe] instances sharing this backend; evicted at 0. */
    val refCount = java.util.concurrent.atomic.AtomicInteger(0)

    /** Shared engine, created lazily on first production use (never for tests). */
    @Volatile
    var engine: AndroidKeystoreEncryption? = null

    fun engineOrCreate(create: () -> AndroidKeystoreEncryption): AndroidKeystoreEncryption {
        engine?.let { return it }
        return synchronized(this) { engine ?: create().also { engine = it } }
    }
}

// Live backends by absolute path; per-path check-then-act is serialized by [pathLock].
private val backends = ConcurrentHashMap<String, AndroidBackend>()

// Evicted backend's scope, awaited before a recreate: DataStore frees a file only once its
// scope's Job completes, else the new DataStore hits "multiple DataStores active".
private val terminatingScopes = ConcurrentHashMap<String, CoroutineScope>()

// One monitor per path so a file never has two DataStores constructed concurrently.
private val pathLocks = ConcurrentHashMap<String, Any>()
private fun pathLock(path: String): Any = pathLocks.computeIfAbsent(path) { Any() }

// Shared backend for [path], created atomically on first use and ref-counted. A recreate
// awaits the prior owner's teardown, since DataStore frees the file only when its scope ends.
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

// Drops one ref; the last release evicts the entry, parks the scope for the next recreate
// to await, and cancels it. Each [KSafe] must release exactly once.
private fun releaseBackend(path: String) = synchronized(pathLock(path)) {
    val backend = backends[path] ?: return
    if (backend.refCount.decrementAndGet() <= 0) {
        backends.remove(path)
        terminatingScopes[path] = backend.scope
        backend.scope.cancel()
    }
}

/**
 * Android factory for [KSafe]; same call syntax as the pre-2.0 `KSafe(context, ...)` constructor.
 *
 * @param fileName Optional logical name (lowercase letters / digits / underscores) that
 *   differentiates instances in one process; null uses the default datastore name.
 * @param useStrongBox Deprecated — use `KSafeProtection.HARDWARE_ISOLATED` per property.
 * @param baseDir Optional override for the `.preferences_pb` directory. Null (recommended)
 *   uses the app-private path, where the sandbox enforces permissions. A custom dir is
 *   created if missing but not sandbox-isolated — never point it at external storage
 *   (SD card / `getExternalFilesDir()`) for sensitive data.
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

    // Absolute path uniquely identifies a DataStore: same file → shared DataStore (avoids
    // DataStore's "multiple active instances" error), different dir → separate DataStores.
    val datastoreFile: File = if (baseDir != null) {
        if (!baseDir.exists()) baseDir.mkdirs()
        File(baseDir, "$baseFileName.preferences_pb")
    } else {
        context.preferencesDataStoreFile(baseFileName)
    }

    // Per-path shared backend (DataStore + scope + engine); see [AndroidBackend].
    val datastorePath = datastoreFile.absolutePath
    val backend = acquireBackend(datastorePath) { scope ->
        PreferenceDataStoreFactory.create(
            // Quarantine a corrupt .preferences_pb and continue from empty, rather than throwing
            // on every read forever (which crashes the collector); corrupt bytes are copied aside.
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

    // One storage shared by engine and core, so each safe's DEK lives in its own DataStore.
    // The production engine is created lazily and shared, so instances on this file share one
    // DEK cache over the single wrapped-DEK slot.
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

    // Honors the deprecated useStrongBox flag: promotes default-protection encrypted writes to
    // HARDWARE_ISOLATED; explicit protection levels pass through unchanged.
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
            // Drop this instance's backend ref (only the last release cancels the scope).
            // cancel() is idempotent, so guard to exactly one decrement per instance.
            if (released.compareAndSet(false, true)) releaseBackend(datastorePath)
        },
    )

    // Android custody is fixed at construction (no runtime fallback), so snapshot it.
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
            // Relaxed DEFAULT values use a DEK wrapped by the non-exportable TEE master key;
            // the unwrapped DEK lives in process memory after first use. HARDWARE_ISOLATED and
            // the strict requireUnlockedDevice master keep keys inside the TEE on every op.
            add("relaxed_default_uses_software_dek")
        },
    )
    return KSafe(
        core = core,
        deviceKeyStorages = deviceKeyStorages,
        protectionInfoProvider = { protectionInfoSnapshot },
    )
}
