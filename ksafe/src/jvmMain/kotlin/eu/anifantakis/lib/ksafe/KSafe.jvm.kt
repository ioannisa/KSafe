package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
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
 *   [KSafeMemoryPolicy.ENCRYPTED]).
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
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
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
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
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
    val datastoreFile = File(resolvedBaseDir, "$baseFileName.preferences_pb")

    val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
        produceFile = { datastoreFile }
    )

    val engine: KSafeEncryption = testEngine ?: JvmSoftwareEncryption(config, dataStore)

    val core = KSafeCore(
        storage = DataStoreStorage(dataStore),
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = { _, _ -> KSafeKeyStorage.SOFTWARE },
        lazyLoad = lazyLoad,
        keyAlias = { userKey -> fileName?.let { "$it:$userKey" } ?: userKey },
    )

    return KSafe(
        core = core,
        deviceKeyStorages = setOf(KSafeKeyStorage.SOFTWARE),
        // Belt-and-braces: also remove the physical DataStore file after
        // `core.clearAll()`. Some tests assert on file absence, and
        // `DataStore.edit { clear() }` leaves an empty protobuf behind.
        onClearAllCleanup = {
            try {
                if (datastoreFile.exists()) datastoreFile.delete()
            } catch (_: Exception) { /* best-effort */ }
        },
    )
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
