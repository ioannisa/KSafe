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

/**
 * Public — tests and users rely on this top-level helper to encode raw
 * ciphertext for inspection/assertion.
 */
@OptIn(ExperimentalEncodingApi::class)
fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

private val fileNameRegex = Regex("[a-z][a-z0-9_]*")

/**
 * Sentinel for the per-datastore master key created by the v2 envelope. JVM
 * has no "device locked" concept so the locked-vs-unlocked split collapses
 * to a single alias — both `requireUnlockedDevice = true` and `false` route
 * here. Reserved by the leading-`__` / trailing-`__` convention used
 * everywhere else in KSafe.
 */
private const val MASTER_KEY_DEFAULT: String = "__ksafe_master__"

/**
 * JVM factory for [KSafe]. Resolves to the same call syntax as the pre-2.0
 * `KSafe(...)` constructor — Kotlin treats top-level `KSafe(...)` and a
 * primary constructor identically at the call site.
 *
 * The factory wires up the JVM-specific concerns (DataStore file location,
 * POSIX permissions on the base directory, the [JvmSoftwareEncryption] engine,
 * extra `clearAll` file cleanup) and hands them to the shared
 * [KSafeCore] orchestrator.
 *
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
 * @param baseDir Optional override for the directory in which the DataStore
 *   `.preferences_pb` file is stored. If null (default) KSafe uses
 *   `~/.eu_anifantakis_ksafe`. If provided, KSafe will create the directory if
 *   it doesn't exist and apply POSIX 0700 permissions on POSIX file systems.
 *   The caller-supplied directory must be on a local file system the process
 *   can write to. Useful for storing data in your application's working
 *   directory, `$XDG_DATA_HOME`, `%APPDATA%`, or a per-test temp directory.
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

/**
 * Internal test variant — accepts a pre-built [KSafeEncryption] so tests can
 * inject a fake engine without going through `JvmSoftwareEncryption`.
 */
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
 * Per-file shared backend for the JVM factory. Jetpack DataStore (and the JSON-fallback
 * `DataStoreFactory`) refuse two active instances on the same file — and release a file only
 * once the owning scope's [Job] completes. Constructing a fresh storage/engine per [KSafe]
 * therefore (1) trips the "multiple DataStores active for the same file" guard when two live
 * instances share a `fileName` (swallowed by the cache-load catch → silent defaults + dropped
 * writes), and (2) races teardown on close→recreate. This registry shares ONE backend per
 * resolved path, ref-counted (only the last close tears the scope down) with a bounded
 * prior-scope await before a recreate — mirroring the Android factory (deep-review #51).
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
 * Returns the shared backend for [path], creating it (atomically, per path) on first use and
 * incrementing its ref-count. A recreate after the previous owner closed awaits that owner's
 * teardown first (bounded), since DataStore frees a file only once its scope completes.
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

    // Resolve the storage directory once. Both the produceFile lambda and the
    // onClearAllCleanup callback use this exact path so they stay in sync —
    // before the fix, cleanup hardcoded the home dir and lost the file when
    // baseDir was set.
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

    // #6: when appNamespace is explicitly set, isolate the DATA FILE by it (not
    // just the OS-vault keys), so two apps sharing a `fileName` on one OS account
    // don't clobber a single DataStore/JSON file. Files go in a per-namespace
    // subdirectory; apps that DON'T set appNamespace keep the historical
    // un-namespaced path unchanged (no path change, no migration for them).
    val explicitNamespace = config.appNamespace
        ?.replace(Regex("[^A-Za-z0-9._-]"), "_")
        ?.trimStart('.')          // never "." / ".." → no path traversal
        ?.take(120)
        ?.takeIf { it.isNotBlank() }
    val storageDir: File = if (explicitNamespace != null) {
        File(resolvedBaseDir, explicitNamespace).also { nsDir ->
            if (!nsDir.exists()) nsDir.mkdirs()
            secureDirectory(nsDir)
            // One-time, best-effort COPY of any pre-existing un-namespaced files
            // into the subdir so existing appNamespace users keep their data.
            // COPY (not move): one app can't steal another's shared file, and
            // cross-app entries that don't decrypt with this app's keys just read
            // back as defaults — no data loss either way.
            for (suffix in listOf(".preferences_pb", ".ksafe.json", ".ksafe-keys.json", ".ksafe.json.migrated")) {
                val src = File(resolvedBaseDir, baseFileName + suffix)
                val dst = File(nsDir, baseFileName + suffix)
                if (src.exists() && !dst.exists()) runCatching { src.copyTo(dst, overwrite = false) }
            }
        }
    } else {
        resolvedBaseDir
    }

    // Key-alias scheme — defined once and shared by KSafeCore and the
    // fallback→OS-backed migration so both compute byte-identical aliases.
    val keyAlias: (String) -> String = { userKey -> fileName?.let { "$it:$userKey" } ?: userKey }
    val masterAlias: (Boolean) -> String = { _ -> fileName?.let { "$it:$MASTER_KEY_DEFAULT" } ?: MASTER_KEY_DEFAULT }

    // Acquire the per-file shared backend (storage + scope + engine + clearAll cleanup),
    // ref-counted so co-existing instances on one file share a single DataStore + engine and
    // only the last close tears the scope down; creation is atomic per path and a recreate
    // awaits the prior owner's teardown (deep-review #51). The path key identifies the safe
    // regardless of which backend (DataStore vs JSON fallback) is selected.
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
            // No key for plain values → SOFTWARE (nothing to protect).
            // Otherwise: the active vault decides — SANDBOX_PROTECTED when an
            // OS vault holds the key, SOFTWARE when the fallback / opt-out is
            // active. Matches the instance-level protectionInfo.effectiveLevel.
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
        // Recomputed per-access so a runtime `degradeToLegacy` (Compose
        // Desktop release distributable hitting LinkageError) is reflected
        // in the public `KSafe.protectionInfo` getter.
        protectionInfoProvider = { jvmProtectionInfo(backend.engine) },
        onClearAllCleanup = backend.clearAllCleanup,
    )
}

/**
 * Builds the storage + engine + clearAll-cleanup for one file on the JVM, selecting the
 * normal DataStore backend or the no-`sun.misc.Unsafe` JSON-file fallback, and running the
 * one-time JSON→OS-backed forward migration. Invoked once per [JvmBackend] (i.e. once per
 * file path), under that path's acquisition lock.
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
        // ── JSON-file fallback ───────────────────────────────────────────────
        // `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is missing — typically
        // a Compose Desktop release distributable whose jlink runtime was trimmed.
        // Jetpack DataStore's protobuf hard-requires Unsafe and would crash, so we
        // persist to a plain JSON file instead (software-encrypted; no OS-backed
        // keys, but data is NOT lost). Add modules("jdk.unsupported") to restore
        // the DataStore + OS-keyvault path.
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
        // ── Normal DataStore path (Unsafe present, or a test engine injected) ──
        val datastoreFile = File(storageDir, "$baseFileName.preferences_pb")
        val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
            // A corrupt .preferences_pb otherwise throws CorruptionException on every read
            // forever: the background collector crashes (uncaught in its scope) and getDirect
            // silently returns defaults while suspend get() throws (deep-review #23). Quarantine
            // the unreadable file (copy aside for recovery) and continue from an empty store —
            // the same posture as the JSON-fallback backend. The corrupt bytes are preserved.
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
            // Belt-and-braces: also remove the physical DataStore file after
            // `core.clearAll()` (DataStore's own `clear()` leaves an empty file).
            try {
                if (datastoreFile.exists()) datastoreFile.delete()
            } catch (_: Exception) { /* best-effort */ }
            // Even on the OS-backed path, a PRIOR run's JSON fallback may have left
            // recoverable residue in this dir; clearAll() must wipe it too (#35).
            deleteResidualFallbackFiles(storageDir, baseFileName)
        }

        // One-time forward migration: if an earlier run persisted through the
        // no-`Unsafe` JSON fallback, re-encrypt that data under the OS-backed key
        // so it carries forward instead of appearing empty. Cheap `exists()`
        // pre-gate (common path costs nothing); the migration itself only
        // proceeds when the OS-backed store has no user data yet. Skipped for
        // test-injected engines.
        if (testEngine == null) {
            val jsonFallback = File(storageDir, "$baseFileName.ksafe.json")
            val migrationMarker = File(storageDir, "$baseFileName.ksafe.json.migrated")
            // Migrate when a live fallback file exists AND it is NEWER than the last
            // migration's marker. Gating on `!marker.exists()` alone (the old code) broke the
            // documented toggle case (deep-review #32): after one migration the marker is a
            // permanent `.migrated` archive that nothing deletes, so a SECOND fallback period
            // (modules dropped again → fresh `.ksafe.json` with new data → modules restored)
            // was skipped forever and that data never reached the OS-backed store. Comparing
            // mtimes distinguishes "fresh fallback data written after the last migration"
            // (migrate) from "a stale source a prior clean pass couldn't rename away — its
            // write predates the marker" (skip, so we don't re-drain on every launch).
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
 * Deletes residual JVM-fallback files that still hold recoverable secrets — the
 * `*.migrated` archives left by a completed JSON→OS-backed migration (the keys archive is
 * the **plaintext** AES bytes, the JSON archive the ciphertext they decrypt) and the
 * `*.corrupt-<ts>` quarantine copies [DataStoreJsonStorage] makes on corruption. `clearAll()`
 * promises a full wipe including key deletion, but these siblings of the live store were left
 * behind, so anyone with file access could decrypt every pre-migration secret offline —
 * defeating the wipe (deep-review #35). Matched precisely by the `<baseFileName>.ksafe`
 * prefix so a sibling safe's files in the same dir aren't touched. Best-effort.
 */
private fun deleteResidualFallbackFiles(storageDir: File, baseFileName: String) {
    runCatching {
        val prefix = "$baseFileName.ksafe"
        storageDir.listFiles()?.forEach { f ->
            val n = f.name
            if (n.startsWith(prefix) && (n.endsWith(".migrated") || n.contains(".corrupt-"))) {
                runCatching { f.delete() }
            }
        }
    }
}

/**
 * Builds [KSafeProtectionInfo] for the JVM target.
 *
 * Reads the active vault descriptor from [JvmSoftwareEncryption] when that's
 * the engine in use. For test-injected engines (the internal `KSafe(...,
 * testEngine = …)` overload), there's no vault to introspect, so we report
 * the engine's class name as custody and leave the level at the intended
 * baseline — tests that care about protection state inject their own value
 * by going through the production path.
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
 * True iff `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is on the runtime.
 * Drives the JVM storage-backend selection in [buildJvmKSafe]: Jetpack
 * DataStore's protobuf hard-requires `sun.misc.Unsafe`, so on a `jlink`-trimmed
 * runtime that omits it (Compose Desktop release distributable) KSafe falls back
 * to [DataStoreJsonStorage] instead of crashing inside DataStore.
 */
private fun isSunMiscUnsafePresent(): Boolean = try {
    Class.forName("sun.misc.Unsafe", false, KSafe::class.java.classLoader)
    true
} catch (_: Throwable) {
    false
}

private val jsonFallbackWarned = java.util.concurrent.atomic.AtomicBoolean(false)

/**
 * One-time notice that KSafe is running on the JSON-file fallback because
 * `sun.misc.Unsafe` is unavailable. Not fatal — data persists (software-
 * encrypted); the user just loses OS-backed key custody and the DataStore
 * backend until they add the module.
 */
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

// ---------- Test-surface extensions ----------
//
// Tests historically reach into the JVM `KSafe` for whitebox assertions:
// - `ksafe.dataStore` to read/write the underlying DataStore directly
// - `ksafe.engine` to encrypt/decrypt with the active engine
// - `ksafe.updateCache(prefs)` to merge a snapshot into the in-memory cache
//
// With KSafe now in commonMain (no platform members), these hooks live as
// platform-source-set extensions. Same package as `KSafe` so tests don't need
// new imports.

@PublishedApi
internal val KSafe.dataStore: DataStore<Preferences>
    get() = (core.storage as DataStoreStorage).dataStore

@PublishedApi
internal val KSafe.engine: KSafeEncryption
    get() = core.engine

/**
 * Used by tests to deterministically merge a DataStore snapshot into the
 * core's in-memory cache. Keeps the pre-refactor test surface intact.
 */
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
    // core.updateCache is now suspend (to support async decrypt on web);
    // JVM has blocking crypto so wrapping in runBlocking is fine here.
    kotlinx.coroutines.runBlocking { core.updateCache(out) }
}
