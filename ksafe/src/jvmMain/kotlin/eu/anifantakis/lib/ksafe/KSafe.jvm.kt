package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.emptyPreferences
import eu.anifantakis.lib.ksafe.internal.DataStoreJsonStorage
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.migrateJsonFallbackToOsBacked
import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Encodes raw bytes (e.g. ciphertext) as Base64. */
@OptIn(ExperimentalEncodingApi::class)
fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

private val fileNameRegex = Regex("[a-z][a-z0-9_]*")

/** v2-envelope master-key alias; JVM has no locked/unlocked split, so both policies route here. */
private const val MASTER_KEY_DEFAULT: String = "__ksafe_master__"

/**
 * Creates a JVM [KSafe] whose data lives under [baseDir] (default
 * `~/.eu_anifantakis_ksafe`, created if missing with POSIX 0700 permissions).
 */
fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    baseDir: File? = null,
): KSafe = buildJvmKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    memoryPolicy = memoryPolicy,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    baseDir = baseDir,
    testEngine = null,
)

/** Test variant: accepts a pre-built [KSafeEncryption] engine. */
@PublishedApi
internal fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    baseDir: File? = null,
    testEngine: KSafeEncryption,
): KSafe = buildJvmKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    memoryPolicy = memoryPolicy,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    baseDir = baseDir,
    testEngine = testEngine,
)

/**
 * Per-file shared backend: DataStore refuses two active instances on one file, so live
 * [KSafe] instances sharing a path share one ref-counted backend (last close tears it down).
 */
private class JvmBackend(
    val storage: KSafePlatformStorage,
    val scope: CoroutineScope,
    val engine: KSafeEncryption,
    val clearAllCleanup: suspend () -> Unit,
) {
    val refCount = java.util.concurrent.atomic.AtomicInteger(0)
}

private val jvmBackends = java.util.concurrent.ConcurrentHashMap<String, JvmBackend>()
private val jvmTerminatingScopes = java.util.concurrent.ConcurrentHashMap<String, CoroutineScope>()
private val jvmPathLocks = java.util.concurrent.ConcurrentHashMap<String, Any>()
private fun jvmPathLock(path: String): Any = jvmPathLocks.computeIfAbsent(path) { Any() }

/**
 * Returns the ref-counted backend for [path], creating it atomically on first use. A recreate
 * awaits the prior owner's teardown (bounded): DataStore frees a file only when its scope completes.
 */
private fun acquireJvmBackend(
    path: String,
    create: (CoroutineScope) -> JvmBackend,
): JvmBackend = synchronized(jvmPathLock(path)) {
    jvmBackends[path]?.let {
        it.refCount.incrementAndGet()
        return it
    }
    jvmTerminatingScopes.remove(path)?.coroutineContext?.get(Job)?.let { priorJob ->
        runBlocking { withTimeoutOrNull(2_000) { priorJob.join() } }
    }
    val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    val backend = create(scope).also { it.refCount.set(1) }
    jvmBackends[path] = backend
    backend
}

/** Drops one ref; the last release evicts the entry, parks the scope for a later recreate to
 *  await, and cancels it. Each [KSafe] must call this at most once (guarded by the caller). */
private fun releaseJvmBackend(path: String) = synchronized(jvmPathLock(path)) {
    val backend = jvmBackends[path] ?: return
    if (backend.refCount.decrementAndGet() <= 0) {
        jvmBackends.remove(path)
        jvmTerminatingScopes[path] = backend.scope
        backend.scope.cancel()
    }
}

private fun buildJvmKSafe(
    fileName: String?,
    lazyLoad: Boolean,
    memoryPolicy: KSafeMemoryPolicy,
    config: KSafeConfig,
    securityPolicy: KSafeSecurityPolicy,
    plaintextCacheTtl: Duration,
    baseDir: File?,
    testEngine: KSafeEncryption?,
): KSafe {
    if (fileName != null && !fileName.matches(fileNameRegex)) {
        throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores")
    }
    validateSecurityPolicy(securityPolicy)

    val resolvedBaseDir: File = baseDir ?: File(
        Paths.get(System.getProperty("user.home")).toFile(),
        ".eu_anifantakis_ksafe",
    )
    if (!resolvedBaseDir.exists()) {
        resolvedBaseDir.mkdirs()
    }
    secureDirectory(resolvedBaseDir)

    val baseFileName = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" }
        ?: "eu_anifantakis_ksafe_datastore"

    // An explicit appNamespace isolates the data file (per-namespace subdir) too, not just the
    // OS-vault keys; apps without one keep the historical un-namespaced path.
    val explicitNamespace = config.appNamespace
        ?.replace(Regex("[^A-Za-z0-9._-]"), "_")
        ?.trimStart('.')          // never "." / ".." → no path traversal
        ?.take(120)
        ?.takeIf { it.isNotBlank() }
    val storageDir: File = if (explicitNamespace != null) {
        File(resolvedBaseDir, explicitNamespace).also { nsDir ->
            if (!nsDir.exists()) nsDir.mkdirs()
            secureDirectory(nsDir)
            // Copy (never move) pre-existing un-namespaced files: a move would steal another
            // app's shared file; undecryptable entries just read as defaults.
            for (suffix in listOf(".preferences_pb", ".ksafe.json", ".ksafe-keys.json", ".ksafe.json.migrated")) {
                val src = File(resolvedBaseDir, baseFileName + suffix)
                val dst = File(nsDir, baseFileName + suffix)
                if (src.exists() && !dst.exists()) runCatching { src.copyTo(dst, overwrite = false) }
            }
        }
    } else {
        resolvedBaseDir
    }

    // Alias scheme shared by KSafeCore and the fallback migration so both compute identical aliases.
    val keyAlias: (String) -> String = { userKey -> fileName?.let { "$it:$userKey" } ?: userKey }
    val masterAlias: (Boolean) -> String = { _ -> fileName?.let { "$it:$MASTER_KEY_DEFAULT" } ?: MASTER_KEY_DEFAULT }

    // Identifies the safe regardless of which backend (DataStore vs JSON fallback) is selected.
    val backendPath = File(storageDir, baseFileName).absolutePath
    val backend = acquireJvmBackend(backendPath) { storageScope ->
        createJvmBackend(
            storageScope = storageScope,
            storageDir = storageDir,
            baseFileName = baseFileName,
            config = config,
            testEngine = testEngine,
            keyAlias = keyAlias,
            masterAlias = masterAlias,
        )
    }

    // Guards this instance's single backend release (KSafeCore.cancel() is idempotent).
    val released = java.util.concurrent.atomic.AtomicBoolean(false)

    val core = KSafeCore(
        storage = backend.storage,
        engineProvider = { backend.engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = { _, _ -> KSafeKeyStorage.SOFTWARE },
        resolveKeyLevel = { _, protection ->
            // Plain values have no key; otherwise the active vault decides (OS-backed →
            // SANDBOX_PROTECTED, fallback/opt-out → SOFTWARE).
            val eng = backend.engine
            when {
                protection == null -> KSafeProtectionLevel.SOFTWARE
                eng is JvmSoftwareEncryption && eng.keyVaultIsOsBacked ->
                    KSafeProtectionLevel.SANDBOX_PROTECTED
                eng is JvmSoftwareEncryption ->
                    KSafeProtectionLevel.SOFTWARE
                else -> KSafeProtectionLevel.SANDBOX_PROTECTED   // test-injected engine: assume baseline
            }
        },
        lazyLoad = lazyLoad,
        keyAlias = keyAlias,
        masterAlias = masterAlias,
        onCancel = { if (released.compareAndSet(false, true)) releaseJvmBackend(backendPath) },
    )

    return KSafe(
        core = core,
        deviceKeyStorages = setOf(KSafeKeyStorage.SOFTWARE),
        // Recomputed per access so a runtime degrade shows up in `KSafe.protectionInfo`.
        protectionInfoProvider = { jvmProtectionInfo(backend.engine) },
        onClearAllCleanup = backend.clearAllCleanup,
    )
}

/**
 * Builds the storage + engine + clearAll-cleanup for one file, selecting the normal DataStore
 * backend or the no-`sun.misc.Unsafe` JSON-file fallback and running the one-time
 * JSON→OS-backed forward migration. Invoked once per file path, under that path's lock.
 */
private fun createJvmBackend(
    storageScope: CoroutineScope,
    storageDir: File,
    baseFileName: String,
    config: KSafeConfig,
    testEngine: KSafeEncryption?,
    keyAlias: (String) -> String,
    masterAlias: (Boolean) -> String,
): JvmBackend {
    val storage: KSafePlatformStorage
    val engine: KSafeEncryption
    val clearAllCleanup: suspend () -> Unit

    if (testEngine == null && !isSunMiscUnsafePresent()) {
        // JSON-file fallback: `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is missing
        // (typically a jlink-trimmed Compose Desktop distributable). DataStore's protobuf
        // hard-requires it and would crash, so persist to a plain JSON file instead
        // (software-encrypted, no OS-backed keys, but data is NOT lost). Adding
        // modules("jdk.unsupported") restores the DataStore + OS-keyvault path.
        warnUsingJsonFileFallbackOnce()
        val jsonFile = File(storageDir, "$baseFileName.ksafe.json")
        val keysFile = File(storageDir, "$baseFileName.ksafe-keys.json")
        storage = DataStoreJsonStorage(jsonFile, storageScope)
        engine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
        )
        clearAllCleanup = {
            runCatching { if (jsonFile.exists()) jsonFile.delete() }
            runCatching { if (keysFile.exists()) keysFile.delete() }
            deleteResidualFallbackFiles(storageDir, baseFileName)
        }
    } else {
        // Normal DataStore path (Unsafe present, or a test engine injected).
        val datastoreFile = File(storageDir, "$baseFileName.preferences_pb")
        val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
            // A corrupt .preferences_pb otherwise throws CorruptionException on every read
            // forever. Quarantine the unreadable file (copy aside for recovery) and continue
            // from an empty store — same posture as the JSON-fallback backend.
            corruptionHandler = ReplaceFileCorruptionHandler {
                runCatching {
                    datastoreFile.copyTo(
                        File(datastoreFile.parentFile, "${datastoreFile.name}.corrupt-${System.currentTimeMillis()}"),
                        overwrite = false,
                    )
                }
                emptyPreferences()
            },
            scope = storageScope,
            produceFile = { datastoreFile }
        )
        storage = DataStoreStorage(dataStore)
        engine = testEngine ?: JvmSoftwareEncryption(config, dataStore)
        clearAllCleanup = {
            // Also remove the physical DataStore file after `core.clearAll()` (DataStore's own
            // `clear()` leaves an empty file behind).
            try {
                if (datastoreFile.exists()) datastoreFile.delete()
            } catch (_: Exception) { /* best-effort */ }
            // The corruption handler above quarantines an unreadable store as
            // `<base>.preferences_pb.corrupt-<ts>`, a copy still holding decryptable
            // ciphertext; clearAll() promises a full wipe, so remove those siblings too
            // (deleteResidualFallbackFiles only matches the `<base>.ksafe` prefix). Matched by
            // the exact datastore file-name prefix so a sibling safe's files aren't touched.
            runCatching {
                val corruptPrefix = "${datastoreFile.name}.corrupt-"
                storageDir.listFiles()?.forEach { f ->
                    if (f.name.startsWith(corruptPrefix)) runCatching { f.delete() }
                }
            }
            // A prior run's JSON fallback may have left recoverable residue here even on the
            // OS-backed path; clearAll() must wipe it too.
            deleteResidualFallbackFiles(storageDir, baseFileName)
        }

        // One-time forward migration: if an earlier run persisted through the no-`Unsafe` JSON
        // fallback, re-encrypt that data under the OS-backed key so it carries forward instead
        // of appearing empty. The fallback values win over anything already in the target —
        // except, on a retry after a transient failure, keys the user wrote in the target since
        // that failed attempt (tracked via `.migration-pending`). Skipped for test engines.
        if (testEngine == null) {
            val jsonFallback = File(storageDir, "$baseFileName.ksafe.json")
            val migrationMarker = File(storageDir, "$baseFileName.ksafe.json.migrated")
            // Migrate when a live fallback file exists AND is newer than the last migration's
            // marker. Gating on `!marker.exists()` alone would skip a second fallback period
            // forever (the `.migrated` archive is permanent), so data from a later modules-off →
            // modules-on toggle would never reach the OS-backed store. Comparing mtimes
            // distinguishes fresh fallback data (migrate) from a stale source a prior clean pass
            // couldn't rename away (skip, so we don't re-drain every launch).
            val needsMigration = jsonFallback.exists() &&
                (!migrationMarker.exists() || jsonFallback.lastModified() > migrationMarker.lastModified())
            if (needsMigration) {
                migrateJsonFallbackToOsBacked(
                    config = config,
                    jsonFallback = jsonFallback,
                    keysFallback = File(storageDir, "$baseFileName.ksafe-keys.json"),
                    target = storage,
                    targetEngine = engine,
                    keyAlias = keyAlias,
                    masterAlias = masterAlias,
                )
            }
        }
    }

    return JvmBackend(storage, storageScope, engine, clearAllCleanup)
}

/**
 * Deletes residual JVM-fallback files that still hold recoverable secrets: the `*.migrated`
 * archives from a completed JSON→OS-backed migration (the keys archive is the plaintext AES
 * bytes, the JSON archive the ciphertext they decrypt), the `*.corrupt-<ts>` quarantine
 * copies, and the live `<base>.ksafe.json` / `<base>.ksafe-keys.json` a prior no-`Unsafe`
 * period may have left. clearAll() promises a full wipe including key deletion; leaving any
 * of these would let anyone with file access decrypt every pre-migration secret offline.
 * Matched by the `<baseFileName>.ksafe` prefix so a sibling safe's files aren't touched.
 */
private fun deleteResidualFallbackFiles(storageDir: File, baseFileName: String) {
    runCatching {
        val prefix = "$baseFileName.ksafe"
        val liveJson = "$baseFileName.ksafe.json"
        val liveKeys = "$baseFileName.ksafe-keys.json"
        storageDir.listFiles()?.forEach { f ->
            val n = f.name
            if (n.startsWith(prefix) &&
                (n == liveJson || n == liveKeys ||
                    // Crash-leftover temp files from FileKeyVault.write() — each is a full plaintext
                    // copy of the AES key map (`<base>.ksafe-keys.json<random>.tmp`).
                    (n.startsWith(liveKeys) && n.endsWith(".tmp")) ||
                    n.endsWith(".migrated") || n.endsWith(".migration-pending") || n.contains(".corrupt-"))
            ) {
                runCatching { f.delete() }
            }
        }
    }
}

/**
 * Builds [KSafeProtectionInfo] for the JVM target from the active vault descriptor. A
 * test-injected engine has no vault to introspect, so it reports the engine's class name as
 * custody and leaves the level at the intended baseline.
 */
private fun jvmProtectionInfo(engine: KSafeEncryption): KSafeProtectionInfo {
    val intended = KSafeProtectionLevel.SANDBOX_PROTECTED
    if (engine !is JvmSoftwareEncryption) {
        return KSafeProtectionInfo(
            intendedLevel = intended,
            effectiveLevel = intended,
            custody = "Test engine: ${engine::class.simpleName}",
            notes = emptyList(),
        )
    }
    val osBacked = engine.keyVaultIsOsBacked
    val optOut = (System.getProperty(PROP_KEY_VAULT) ?: System.getenv(ENV_KEY_VAULT))
        ?.lowercase()
        ?.let { it in OPT_OUT_VALUES } ?: false
    return KSafeProtectionInfo(
        intendedLevel = intended,
        effectiveLevel = if (osBacked) KSafeProtectionLevel.SANDBOX_PROTECTED else KSafeProtectionLevel.SOFTWARE,
        custody = engine.keyVaultName,
        notes = when {
            osBacked -> emptyList()
            optOut   -> listOf("jvm_user_opted_out")
            else     -> listOf("jvm_os_vault_unavailable")
        },
    )
}

private const val PROP_KEY_VAULT = "ksafe.jvm.keyVault"
private const val ENV_KEY_VAULT = "KSAFE_JVM_KEY_VAULT"
private val OPT_OUT_VALUES = setOf("software", "datastore", "off", "false", "none")

/**
 * True iff `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is on the runtime. Drives the
 * storage-backend selection: absent (a jlink-trimmed runtime) falls back to
 * [DataStoreJsonStorage] rather than crashing inside DataStore's protobuf.
 */
private fun isSunMiscUnsafePresent(): Boolean = try {
    Class.forName("sun.misc.Unsafe", false, KSafe::class.java.classLoader)
    true
} catch (_: Throwable) {
    false
}

private val jsonFallbackWarned = java.util.concurrent.atomic.AtomicBoolean(false)

/** One-time notice that KSafe is running on the JSON-file fallback because `sun.misc.Unsafe` is unavailable. */
private fun warnUsingJsonFileFallbackOnce() {
    if (jsonFallbackWarned.compareAndSet(false, true)) {
        System.err.println(
            "KSafe NOTICE: `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is " +
                "missing — using the JSON-file storage fallback. Data still " +
                "persists (software-encrypted in a plain JSON file), but without " +
                "the Jetpack DataStore backend or OS-backed key custody. This is " +
                "usually a Compose Desktop release distributable whose jlink " +
                "runtime was trimmed; add `modules(\"jdk.unsupported\")` to your " +
                "`compose.desktop.application.nativeDistributions` block to restore " +
                "DataStore + the OS keyvault (add `\"java.management\"` too if you " +
                "use a non-default KSafeSecurityPolicy). See docs/JVM_PROTECTION.md."
        )
    }
}

private fun secureDirectory(file: File) {
    try {
        val path = file.toPath()
        if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            val permissions = setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE
            )
            Files.setPosixFilePermissions(path, permissions)
        } else {
            file.setReadable(true, true)
            file.setWritable(true, true)
            file.setExecutable(true, true)
        }
    } catch (e: Exception) {
        System.err.println("KSafe Warning: Could not set secure file permissions: ${e.message}")
    }
}

// Whitebox test hooks. KSafe lives in commonMain (no platform members), so these are
// platform-source-set extensions in the same package.

@PublishedApi
internal val KSafe.dataStore: DataStore<Preferences>
    get() = (core.storage as DataStoreStorage).dataStore

@PublishedApi
internal val KSafe.engine: KSafeEncryption
    get() = core.engine

/** Deterministically merges a DataStore snapshot into the core's in-memory cache (tests). */
@PublishedApi
internal fun KSafe.updateCache(prefs: Preferences) {
    val raw = prefs.asMap()
    val out = HashMap<String, StoredValue>(raw.size)
    for ((k, v) in raw) {
        val sv: StoredValue = when (v) {
            is Boolean -> StoredValue.BoolVal(v)
            is Int -> StoredValue.IntVal(v)
            is Long -> StoredValue.LongVal(v)
            is Float -> StoredValue.FloatVal(v)
            is Double -> StoredValue.DoubleVal(v)
            is String -> StoredValue.Text(v)
            else -> continue
        }
        out[k.name] = sv
    }
    // core.updateCache is suspend for web's async decrypt; JVM crypto is blocking, so runBlocking is fine.
    kotlinx.coroutines.runBlocking { core.updateCache(out) }
}
