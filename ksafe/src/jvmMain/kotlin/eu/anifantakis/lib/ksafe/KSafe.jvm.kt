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
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.KSerializer
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

/**
 * JVM implementation of KSafe.
 *
 * A thin shell over [KSafeCore] — it owns the JVM-specific concerns (DataStore
 * file location, POSIX permissions on the base directory, the
 * [JvmSoftwareEncryption] engine, biometric no-ops) and delegates everything
 * else to the shared orchestrator.
 */
actual class KSafe(
    @PublishedApi internal val fileName: String? = null,
    lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    private val config: KSafeConfig = KSafeConfig(),
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    @PublishedApi internal val plaintextCacheTtl: Duration = 5.seconds,
) {

    @PublishedApi
    internal constructor(
        fileName: String? = null,
        lazyLoad: Boolean = false,
        memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        config: KSafeConfig = KSafeConfig(),
        securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
        plaintextCacheTtl: Duration = 5.seconds,
        testEngine: KSafeEncryption,
    ) : this(fileName, lazyLoad, memoryPolicy, config, securityPolicy, plaintextCacheTtl) {
        _testEngine = testEngine
    }

    @PublishedApi internal var _testEngine: KSafeEncryption? = null

    companion object {
        private val fileNameRegex = Regex("[a-z][a-z0-9_]*")
    }

    actual val deviceKeyStorages: Set<KSafeKeyStorage> = setOf(KSafeKeyStorage.SOFTWARE)

    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores")
        }
        validateSecurityPolicy(securityPolicy)
    }

    @PublishedApi
    internal val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
        produceFile = {
            val homeDir = Paths.get(System.getProperty("user.home")).toFile()
            val baseDir = File(homeDir, ".eu_anifantakis_ksafe")
            if (!baseDir.exists()) {
                baseDir.mkdirs()
                secureDirectory(baseDir)
            }
            val base = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" }
                ?: "eu_anifantakis_ksafe_datastore"
            File(baseDir, "$base.preferences_pb")
        }
    )

    // Lazy so that `_testEngine` (set by the secondary constructor) is honoured.
    @PublishedApi
    internal val engine: KSafeEncryption by lazy {
        _testEngine ?: JvmSoftwareEncryption(config, dataStore)
    }

    // Core starts its background collector + write consumer eagerly. Safe to
    // construct here because KSafeCore resolves its engine lazily through the
    // provider below — by the time a coroutine actually dereferences it the
    // secondary constructor body has already set `_testEngine`.
    @PublishedApi
    internal val core: KSafeCore = KSafeCore(
        storage = DataStoreStorage(dataStore),
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = { _, _ -> KSafeKeyStorage.SOFTWARE },
        lazyLoad = lazyLoad,
        keyAlias = { userKey -> fileName?.let { "$it:$userKey" } ?: userKey },
    )

    /**
     * Used by tests to deterministically merge a DataStore snapshot into the
     * core's in-memory cache. Keeps the pre-refactor test surface intact.
     */
    @PublishedApi
    internal fun updateCache(prefs: Preferences) {
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

    @PublishedApi
    internal actual fun defaultEncryptedMode(): KSafeWriteMode =
        KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)

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

    // ---------- Raw API (delegates to core) ----------

    @PublishedApi
    internal actual fun getDirectRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? =
        core.getDirectRaw(key, defaultValue, serializer)

    @PublishedApi
    internal actual fun putDirectRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) =
        core.putDirectRaw(key, value, mode, serializer)

    @PublishedApi
    internal actual suspend fun getRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? =
        core.getRaw(key, defaultValue, serializer)

    @PublishedApi
    internal actual fun getFlowRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Flow<Any?> =
        core.getFlowRaw(key, defaultValue, serializer)

    @PublishedApi
    internal actual suspend fun putRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) =
        core.putRaw(key, value, mode, serializer)

    actual fun deleteDirect(key: String) = core.deleteDirect(key)
    actual suspend fun delete(key: String) = core.delete(key)
    actual fun getKeyInfo(key: String): KSafeKeyInfo? = core.getKeyInfo(key)

    actual suspend fun clearAll() {
        core.clearAll()
        // Belt-and-braces: also remove the physical DataStore file. Some tests
        // assert on file absence, and `DataStore.edit { clear() }` leaves an
        // empty protobuf behind.
        try {
            val homeDir = Paths.get(System.getProperty("user.home")).toFile()
            val baseDir = File(homeDir, ".eu_anifantakis_ksafe")
            val base = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" }
                ?: "eu_anifantakis_ksafe_datastore"
            val file = File(baseDir, "$base.preferences_pb")
            if (file.exists()) file.delete()
        } catch (_: Exception) { /* best-effort */ }
    }

    // ---------- Biometric API (JVM: no hardware, no-op) ----------

    actual suspend fun verifyBiometric(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
    ): Boolean = true

    actual fun verifyBiometricDirect(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
        onResult: (Boolean) -> Unit,
    ) { onResult(true) }

    actual fun clearBiometricAuth(scope: String?) { /* no-op */ }
}
