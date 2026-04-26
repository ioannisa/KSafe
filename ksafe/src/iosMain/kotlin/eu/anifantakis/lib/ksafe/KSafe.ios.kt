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
import platform.Foundation.NSApplicationSupportDirectory
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
 *
 * @param fileName Optional logical file name (lowercase letters / digits /
 *   underscores). If null, the default datastore name is used.
 * @param lazyLoad Defer cache preload until first access.
 * @param memoryPolicy How decrypted values live in RAM (default
 *   [KSafeMemoryPolicy.ENCRYPTED]).
 * @param config Cryptographic + JSON configuration.
 * @param securityPolicy Runtime security checks (jailbreak / debugger / etc.).
 * @param plaintextCacheTtl TTL for the
 *   [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE] policy.
 * @param useSecureEnclave Deprecated — use `KSafeProtection.HARDWARE_ISOLATED`
 *   per property instead.
 * @param directory Optional override for the directory in which the DataStore
 *   `.preferences_pb` file is stored. Pass an absolute path string. If null
 *   (default) KSafe uses `NSApplicationSupportDirectory` — the iOS-correct
 *   location for invisible app data. If you supply a custom path, KSafe
 *   creates the directory if it doesn't exist.
 *
 * **KSafe data is effectively device-local on iOS.** Encryption keys live in
 * the Keychain with `…ThisDeviceOnly` accessibility (and Secure Enclave keys
 * never leave the device for `HARDWARE_ISOLATED` writes), so even if the
 * DataStore file is included in an iCloud Backup, its encrypted bytes are
 * undecryptable on a restored device — the keys are not there. The library
 * does **not** set `NSURLIsExcludedFromBackupKey` on the file because
 * DataStore's atomic-write strategy (write-to-temp then rename) replaces the
 * file's inode and would clobber the extended attribute on every flush.
 * Reliable file-level exclusion is therefore impossible without architectural
 * gymnastics, and the security guarantee already comes from key locality. If
 * you need device-portable preferences, use `UserDefaults`.
 *
 * **Behavior change (2.0):** Pre-2.0 KSafe stored data in
 * `NSDocumentDirectory`, which is iCloud-syncable and exposed via iTunes
 * File Sharing if `UIFileSharingEnabled` is on. The 2.0 default is
 * `NSApplicationSupportDirectory`. **1.x → 2.0 upgrade is automatic:** when
 * the new location is empty AND a legacy file exists at the old
 * `NSDocumentDirectory` path, KSafe moves it on first launch (only when
 * `directory` is null — explicit overrides skip the migration). No app code
 * changes needed.
 */
fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    @Suppress("DEPRECATION") useSecureEnclave: Boolean = false,
    directory: String? = null,
): KSafe = buildIosKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    memoryPolicy = memoryPolicy,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    useSecureEnclave = useSecureEnclave,
    directory = directory,
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
    directory: String? = null,
    testEngine: KSafeEncryption,
): KSafe = buildIosKSafe(
    fileName = fileName,
    lazyLoad = lazyLoad,
    memoryPolicy = memoryPolicy,
    config = config,
    securityPolicy = securityPolicy,
    plaintextCacheTtl = plaintextCacheTtl,
    useSecureEnclave = useSecureEnclave,
    directory = directory,
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
    directory: String?,
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

    val fm = NSFileManager.defaultManager

    // Resolve the DataStore directory once: caller-supplied path, or the
    // platform-recommended NSApplicationSupportDirectory.
    val resolvedDirPath: String = directory
        ?: requireNotNull(
            fm.URLForDirectory(
                directory = NSApplicationSupportDirectory,
                inDomain = NSUserDomainMask,
                appropriateForURL = null,
                create = true,
                error = null,
            )
        ) { "Unable to resolve NSApplicationSupportDirectory" }.path
            ?: error("NSApplicationSupportDirectory has no path")

    // Ensure the directory exists. NSFileManager's URLForDirectory(create=true)
    // creates the system directory; for a caller-supplied path we may also
    // need to mkdir it.
    fm.createDirectoryAtPath(
        resolvedDirPath,
        withIntermediateDirectories = true,
        attributes = null,
        error = null,
    )

    val baseFileName = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" }
        ?: "eu_anifantakis_ksafe_datastore"
    val datastoreFilePath = "$resolvedDirPath/$baseFileName.preferences_pb"

    // 1.x → 2.0 auto-migration: pre-2.0 iOS stored the DataStore in
    // NSDocumentDirectory. If the consumer didn't pass an explicit `directory`
    // and the new location is empty BUT a legacy file exists at the old
    // Documents path, move it. Idempotent — runs only when the new path is
    // empty. Best-effort — failure leaves both files in place; the caller can
    // recover by passing `directory = "<old Documents path>"` if needed.
    if (directory == null && !fm.fileExistsAtPath(datastoreFilePath)) {
        val docsDirPath: String? = fm.URLForDirectory(
            directory = NSDocumentDirectory,
            inDomain = NSUserDomainMask,
            appropriateForURL = null,
            create = false,
            error = null,
        )?.path
        if (docsDirPath != null) {
            val legacyPath = "$docsDirPath/$baseFileName.preferences_pb"
            if (fm.fileExistsAtPath(legacyPath)) {
                val moved = fm.moveItemAtPath(legacyPath, toPath = datastoreFilePath, error = null)
                if (!moved) {
                    println(
                        "KSafe: Failed to migrate legacy DataStore file from \"$legacyPath\" to \"$datastoreFilePath\". " +
                            "If you need access to legacy data, pass `directory = \"$docsDirPath\"` to point at the old location."
                    )
                }
            }
        }
    }

    val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.createWithPath(
        corruptionHandler = null,
        migrations = emptyList(),
        produceFile = { datastoreFilePath.toPath() },
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
