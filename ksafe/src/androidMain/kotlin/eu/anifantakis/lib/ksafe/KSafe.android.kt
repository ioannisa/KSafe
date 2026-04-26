package eu.anifantakis.lib.ksafe

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStoreFile
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
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

private val dataStoreCache = ConcurrentHashMap<String, DataStore<Preferences>>()

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
 *   [KSafeMemoryPolicy.ENCRYPTED]).
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
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
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
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
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

    val dataStore: DataStore<Preferences> = dataStoreCache.getOrPut(datastoreFile.absolutePath) {
        PreferenceDataStoreFactory.create(
            scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
            produceFile = { datastoreFile }
        )
    }

    val engine: KSafeEncryption = testEngine ?: AndroidKeystoreEncryption(config)

    fun resolveKeyStorageTier(userKey: String, protection: KSafeProtection?): KSafeKeyStorage {
        if (protection == null) return KSafeKeyStorage.SOFTWARE
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasStrongBox)
            KSafeKeyStorage.HARDWARE_ISOLATED
        else KSafeKeyStorage.HARDWARE_BACKED
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
        storage = DataStoreStorage(dataStore),
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = ::resolveKeyStorageTier,
        lazyLoad = lazyLoad,
        keyAlias = { userKey ->
            listOfNotNull(KEY_ALIAS_PREFIX, fileName, userKey).joinToString(".")
        },
        modeTransformer = ::promoteMode,
    )

    return KSafe(
        core = core,
        deviceKeyStorages = deviceKeyStorages,
    )
}
