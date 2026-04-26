package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.providers.cryptokit.CryptoKit
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.IosKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.cleanupOrphanedKeychainEntries
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.cinterop.ExperimentalForeignApi
import okio.Path.Companion.toPath
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSURL
import platform.Foundation.NSUserDomainMask
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
private const val SERVICE_NAME = "eu.anifantakis.ksafe"

@PublishedApi
internal const val KEY_PREFIX = "eu.anifantakis.ksafe"

@OptIn(ExperimentalForeignApi::class)
private fun isSimulator(): Boolean =
    NSProcessInfo.processInfo.environment["SIMULATOR_UDID"] != null

/**
 * iOS factory for [KSafe]. Resolves to the same call syntax as the pre-2.0
 * `KSafe(...)` constructor.
 *
 * Owns the iOS-specific concerns:
 * - **CryptoKit registration.** Kotlin/Native's dead-code elimination can
 *   strip `AES.GCM` if nothing references it statically, so the factory body
 *   forces the symbol to be retained.
 * - **Secure Enclave detection.** Simulator = no hardware; real devices
 *   expose the Secure Enclave.
 * - **Legacy encrypted-key format.** Pre-1.8 iOS builds wrote encrypted
 *   entries under `"{fileName}_{key}"` rather than the common
 *   `"encrypted_{key}"`, so we override [KSafeCore]'s legacy key resolver.
 * - **Keychain orphan cleanup.** Runs once, inside the migration hook —
 *   removes Keychain entries whose DataStore counterpart no longer exists.
 */
fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    @Suppress("DEPRECATION") useSecureEnclave: Boolean = false,
): KSafe = buildIosKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    memoryPolicy = memoryPolicy,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    useSecureEnclave = useSecureEnclave,
    testEngine = null,
)

@PublishedApi
internal fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    @Suppress("DEPRECATION") useSecureEnclave: Boolean = false,
    testEngine: KSafeEncryption,
): KSafe = buildIosKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    memoryPolicy = memoryPolicy,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    useSecureEnclave = useSecureEnclave,
    testEngine = testEngine,
)

@OptIn(ExperimentalForeignApi::class)
private fun buildIosKSafe(
    fileName: String?,
    lazyLoad: Boolean,
    memoryPolicy: KSafeMemoryPolicy,
    config: KSafeConfig,
    securityPolicy: KSafeSecurityPolicy,
    plaintextCacheTtl: Duration,
    useSecureEnclave: Boolean,
    testEngine: KSafeEncryption?,
): KSafe {
    if (fileName != null && !fileName.matches(fileNameRegex)) {
        throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores.")
    }
    validateSecurityPolicy(securityPolicy)

    // Force-register CryptoKit + retain AES.GCM so Kotlin/Native DCE can't
    // strip the providers out of the final binary.
    CryptographyProvider.CryptoKit
    @Suppress("UNUSED_VARIABLE") val retainAesGcm = AES.GCM

    val hasSecureEnclave: Boolean = !isSimulator()

    val deviceKeyStorages: Set<KSafeKeyStorage> = buildSet {
        add(KSafeKeyStorage.HARDWARE_BACKED)
        if (hasSecureEnclave) add(KSafeKeyStorage.HARDWARE_ISOLATED)
    }

    val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.createWithPath(
        corruptionHandler = null,
        migrations = emptyList(),
        produceFile = {
            val docDir: NSURL? = NSFileManager.defaultManager.URLForDirectory(
                directory = NSDocumentDirectory,
                inDomain = NSUserDomainMask,
                appropriateForURL = null,
                create = true,
                error = null,
            )
            requireNotNull(docDir).path.plus(
                fileName?.let { "/eu_anifantakis_ksafe_datastore_$it.preferences_pb" }
                    ?: "/eu_anifantakis_ksafe_datastore.preferences_pb"
            ).toPath()
        },
    )

    val engine: KSafeEncryption =
        testEngine ?: IosKeychainEncryption(config = config, serviceName = SERVICE_NAME)

    fun iosKeyAlias(userKey: String): String =
        listOfNotNull(KEY_PREFIX, fileName, userKey).joinToString(".")

    fun iosLegacyEncryptedKey(userKey: String): String =
        fileName?.let { "${it}_$userKey" } ?: KeySafeMetadataManager.legacyEncryptedRawKey(userKey)

    fun iosLegacyEncryptedPrefix(): String =
        fileName?.let { "${it}_" } ?: KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX

    fun resolveKeyStorageTier(userKey: String, protection: KSafeProtection?): KSafeKeyStorage {
        if (protection == null) return KSafeKeyStorage.SOFTWARE
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasSecureEnclave)
            KSafeKeyStorage.HARDWARE_ISOLATED
        else KSafeKeyStorage.HARDWARE_BACKED
    }

    @Suppress("DEPRECATION")
    fun promoteMode(mode: KSafeWriteMode): KSafeWriteMode {
        if (!useSecureEnclave) return mode
        if (mode !is KSafeWriteMode.Encrypted) return mode
        if (mode.protection != KSafeEncryptedProtection.DEFAULT) return mode
        return KSafeWriteMode.Encrypted(
            protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
            requireUnlockedDevice = mode.requireUnlockedDevice,
        )
    }

    /**
     * Runs once per process — removes Keychain entries whose DataStore
     * counterpart is gone. Safe to call eagerly: failures are swallowed so a
     * locked device or transient Keychain error can't block startup.
     */
    suspend fun cleanupOrphanedKeychainEntriesSafe() {
        runCatching {
            cleanupOrphanedKeychainEntries(
                storage = DataStoreStorage(dataStore),
                engine = engine,
                serviceName = SERVICE_NAME,
                keyPrefix = KEY_PREFIX,
                fileName = fileName,
                legacyEncryptedPrefix = iosLegacyEncryptedPrefix(),
                seKeyTagPrefix = IosKeychainEncryption.SE_KEY_TAG_PREFIX,
            )
        }.onFailure { t ->
            println("KSafe: Keychain orphan sweep failed (ignored): ${t.message}")
        }
    }

    val core = KSafeCore(
        storage = DataStoreStorage(dataStore),
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = ::resolveKeyStorageTier,
        migrateAccessPolicy = { cleanupOrphanedKeychainEntriesSafe() },
        lazyLoad = lazyLoad,
        keyAlias = ::iosKeyAlias,
        legacyEncryptedPrefix = iosLegacyEncryptedPrefix(),
        legacyEncryptedKeyFor = ::iosLegacyEncryptedKey,
        modeTransformer = ::promoteMode,
    )

    return KSafe(
        core = core,
        deviceKeyStorages = deviceKeyStorages,
    )
}

// Non-inline helper retained from pre-refactor — external Swift callers may
// reference it for warm-up.
@Suppress("unused")
fun obtainAesGcm(): AES.GCM = CryptographyProvider.CryptoKit.get(AES.GCM)
