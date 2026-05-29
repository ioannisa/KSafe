package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.JsonFileStorage
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
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

    // DataStore launches its own coroutines on the scope we hand it; we
    // hold a reference so KSafe.close() can cancel it. (Unused by the
    // JSON-file fallback, but cheap and harmless.)
    val storageScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

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
        val jsonFile = File(resolvedBaseDir, "$baseFileName.ksafe.json")
        val keysFile = File(resolvedBaseDir, "$baseFileName.ksafe-keys.json")
        storage = JsonFileStorage(jsonFile)
        engine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
        )
        clearAllCleanup = {
            runCatching { if (jsonFile.exists()) jsonFile.delete() }
            runCatching { if (keysFile.exists()) keysFile.delete() }
        }
    } else {
        // ── Normal DataStore path (Unsafe present, or a test engine injected) ──
        val datastoreFile = File(resolvedBaseDir, "$baseFileName.preferences_pb")
        val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
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
        }
    }

    val core = KSafeCore(
        storage = storage,
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = { _, _ -> KSafeKeyStorage.SOFTWARE },
        resolveKeyLevel = { _, protection ->
            // No key for plain values → SOFTWARE (nothing to protect).
            // Otherwise: the active vault decides — SANDBOX_PROTECTED when an
            // OS vault holds the key, SOFTWARE when the fallback / opt-out is
            // active. Matches the instance-level protectionInfo.effectiveLevel.
            when {
                protection == null -> KSafeProtectionLevel.SOFTWARE
                engine is JvmSoftwareEncryption && engine.keyVaultIsOsBacked ->
                    KSafeProtectionLevel.SANDBOX_PROTECTED
                engine is JvmSoftwareEncryption ->
                    KSafeProtectionLevel.SOFTWARE
                else -> KSafeProtectionLevel.SANDBOX_PROTECTED   // test-injected engine: assume baseline
            }
        },
        lazyLoad = lazyLoad,
        keyAlias = { userKey -> fileName?.let { "$it:$userKey" } ?: userKey },
        masterAlias = { _ -> fileName?.let { "$it:$MASTER_KEY_DEFAULT" } ?: MASTER_KEY_DEFAULT },
        onCancel = { storageScope.cancel() },
    )

    return KSafe(
        core = core,
        deviceKeyStorages = setOf(KSafeKeyStorage.SOFTWARE),
        // Recomputed per-access so a runtime `degradeToLegacy` (Compose
        // Desktop release distributable hitting LinkageError) is reflected
        // in the public `KSafe.protectionInfo` getter.
        protectionInfoProvider = { jvmProtectionInfo(engine) },
        onClearAllCleanup = clearAllCleanup,
    )
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
 * to [JsonFileStorage] instead of crashing inside DataStore.
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
