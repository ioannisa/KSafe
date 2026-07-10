package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.emptyPreferences
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.providers.cryptokit.CryptoKit
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeAtomicFlag
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.cleanupOrphanedKeychainEntries
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import okio.Path.Companion.toPath
import platform.Foundation.NSLock
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSUserDomainMask
import kotlin.coroutines.cancellation.CancellationException
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

// Master-key sentinels; the `__…__` convention cannot collide with real user keys.
private const val MASTER_KEY_DEFAULT: String = "__ksafe_master__"
private const val MASTER_KEY_LOCKED: String = "__ksafe_master_locked__"

@OptIn(ExperimentalForeignApi::class)
private fun isSimulator(): Boolean =
    NSProcessInfo.processInfo.environment["SIMULATOR_UDID"] != null

/**
 * Creates a [KSafe] for Apple targets (iOS, iPadOS, macOS): DataStore-backed storage under
 * `NSApplicationSupportDirectory` (or [directory]), with encryption keys held device-only in
 * the Keychain and Secure Enclave wrapping available per write.
 */
fun KSafe(
    fileName: String? = null,
    lazyLoad: Boolean = false,
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    @Suppress("DEPRECATION") useSecureEnclave: Boolean = false,
    directory: String? = null,
): KSafe = buildAppleKSafe(
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
    memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
    config: KSafeConfig = KSafeConfig(),
    securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    plaintextCacheTtl: Duration = 5.seconds,
    @Suppress("DEPRECATION") useSecureEnclave: Boolean = false,
    directory: String? = null,
    testEngine: KSafeEncryption,
): KSafe = buildAppleKSafe(
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

/** Ref-counted per-file DataStore + engine: native DataStore refuses two active instances on
 *  one file and frees it only once the owning scope's [Job] completes. */
private class AppleBackend(
    val dataStore: DataStore<Preferences>,
    val scope: CoroutineScope,
) {
    var refCount: Int = 0
    private var engine: KSafeEncryption? = null

    /** The single shared production engine, created lazily on first use (never for tests). */
    fun engineOrCreate(create: () -> KSafeEncryption): KSafeEncryption {
        appleRegistryLock.lock()
        try {
            return engine ?: create().also { engine = it }
        } finally {
            appleRegistryLock.unlock()
        }
    }
}

/** Guards the backend registry + each backend's refCount/engine. */
private val appleRegistryLock = NSLock()
private val appleBackends = mutableMapOf<String, AppleBackend>()
private val appleTerminatingScopes = mutableMapOf<String, CoroutineScope>()

/** Returns the shared backend for [path], ref-counted; a recreate first awaits (bounded) the
 *  prior owner's teardown, since DataStore frees the file only once its scope completes. */
private fun acquireAppleBackend(
    path: String,
    createDataStore: (CoroutineScope) -> DataStore<Preferences>,
): AppleBackend {
    appleRegistryLock.lock()
    try {
        appleBackends[path]?.let { it.refCount++; return it }
        appleTerminatingScopes.remove(path)?.coroutineContext?.get(Job)?.let { priorJob ->
            runBlocking { withTimeoutOrNull(2_000) { priorJob.join() } }
        }
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        val backend = AppleBackend(createDataStore(scope), scope).also { it.refCount = 1 }
        appleBackends[path] = backend
        return backend
    } finally {
        appleRegistryLock.unlock()
    }
}

/** Drops one ref; the last release evicts the entry, parks the scope for a later recreate to
 *  await, and cancels it. Each [KSafe] must call this at most once (caller-guarded). */
private fun releaseAppleBackend(path: String) {
    appleRegistryLock.lock()
    try {
        val backend = appleBackends[path] ?: return
        backend.refCount--
        if (backend.refCount <= 0) {
            appleBackends.remove(path)
            appleTerminatingScopes[path] = backend.scope
            backend.scope.cancel()
        }
    } finally {
        appleRegistryLock.unlock()
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun buildAppleKSafe(
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

    // Reference CryptoKit + AES.GCM statically so Kotlin/Native DCE can't strip them.
    CryptographyProvider.CryptoKit
    @Suppress("UNUSED_VARIABLE") val retainAesGcm = AES.GCM

    val hasSecureEnclave: Boolean = !isSimulator()

    val deviceKeyStorages: Set<KSafeKeyStorage> = buildSet {
        add(KSafeKeyStorage.HARDWARE_BACKED)
        if (hasSecureEnclave) add(KSafeKeyStorage.HARDWARE_ISOLATED)
    }

    val fm = NSFileManager.defaultManager

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

    // A caller-supplied directory may not exist yet.
    fm.createDirectoryAtPath(
        resolvedDirPath,
        withIntermediateDirectories = true,
        attributes = null,
        error = null,
    )

    val baseFileName = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" }
        ?: "eu_anifantakis_ksafe_datastore"
    val datastoreFilePath = "$resolvedDirPath/$baseFileName.preferences_pb"

    // Moves a legacy DataStore file from NSDocumentDirectory (written by old builds) when the
    // new location is empty and no explicit directory was given. Best-effort and idempotent.
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

    // The scope uses Dispatchers.Default: Kotlin/Native has no Dispatchers.IO, and DataStore's
    // Apple I/O path is non-blocking.
    val backend = acquireAppleBackend(datastoreFilePath) { scope ->
        PreferenceDataStoreFactory.createWithPath(
            // Quarantine a corrupt .preferences_pb and continue from empty instead of throwing
            // CorruptionException on every read; the corrupt bytes are copied aside for recovery.
            corruptionHandler = ReplaceFileCorruptionHandler {
                runCatching {
                    val dest = "$datastoreFilePath.corrupt"
                    val fmgr = NSFileManager.defaultManager
                    fmgr.removeItemAtPath(dest, error = null) // copyItem fails if dest exists
                    fmgr.copyItemAtPath(datastoreFilePath, toPath = dest, error = null)
                }
                emptyPreferences()
            },
            migrations = emptyList(),
            scope = scope,
            produceFile = { datastoreFilePath.toPath() },
        )
    }
    val dataStore: DataStore<Preferences> = backend.dataStore
    val storage = DataStoreStorage(dataStore)

    // One engine per file so co-existing same-file instances don't race master-key creation.
    val engine: KSafeEncryption =
        testEngine ?: backend.engineOrCreate { AppleKeychainEncryption(config = config, serviceName = SERVICE_NAME) }

    // Guards this instance's single backend release (KSafeCore.cancel() is idempotent).
    val released = KSafeAtomicFlag(false)

    fun iosKeyAlias(userKey: String): String =
        listOfNotNull(KEY_PREFIX, fileName, userKey).joinToString(".")

    fun iosMasterAlias(requireUnlockedDevice: Boolean): String {
        val sentinel = if (requireUnlockedDevice) MASTER_KEY_LOCKED else MASTER_KEY_DEFAULT
        return listOfNotNull(KEY_PREFIX, fileName, sentinel).joinToString(".")
    }

    // Handles the legacy "{fileName}_{key}" entry format written by old iOS builds.
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

    fun resolveKeyLevelTier(userKey: String, protection: KSafeProtection?): KSafeProtectionLevel {
        if (protection == null) return KSafeProtectionLevel.SOFTWARE
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasSecureEnclave)
            KSafeProtectionLevel.HARDWARE_ISOLATED
        else KSafeProtectionLevel.HARDWARE_BACKED
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

    /** Orphan sweep with failures swallowed — a locked device or transient Keychain error
     *  must never block startup. */
    suspend fun cleanupOrphanedKeychainEntriesSafe(isUserKeyDirty: (String) -> Boolean) {
        runCatching {
            cleanupOrphanedKeychainEntries(
                storage = storage,
                engine = engine,
                serviceName = SERVICE_NAME,
                keyPrefix = KEY_PREFIX,
                fileName = fileName,
                legacyEncryptedPrefix = iosLegacyEncryptedPrefix(),
                seKeyTagPrefix = AppleKeychainEncryption.SE_KEY_TAG_PREFIX,
                // Shared master keys never appear in the sweep's valid-key set (no single user
                // key references them); reserve them or the sweep orphans all DEFAULT ciphertext.
                reservedKeyIds = setOf(MASTER_KEY_DEFAULT, MASTER_KEY_LOCKED),
                // A write in flight during the sweep commits after our snapshot — don't reap it.
                isInFlight = isUserKeyDirty,
            )
        }.onFailure { t ->
            if (t is CancellationException) throw t
            println("KSafe: Keychain orphan sweep failed (ignored): ${t.message}")
        }
    }

    val core = KSafeCore(
        storage = storage,
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = ::resolveKeyStorageTier,
        resolveKeyLevel = ::resolveKeyLevelTier,
        migrateAccessPolicy = { isUserKeyDirty -> cleanupOrphanedKeychainEntriesSafe(isUserKeyDirty) },
        lazyLoad = lazyLoad,
        keyAlias = ::iosKeyAlias,
        masterAlias = ::iosMasterAlias,
        legacyEncryptedPrefix = iosLegacyEncryptedPrefix(),
        legacyEncryptedKeyFor = ::iosLegacyEncryptedKey,
        modeTransformer = ::promoteMode,
        // Only the last live instance on this file cancels the shared scope; guarded to one
        // release because KSafeCore.cancel() is idempotent.
        onCancel = { if (released.compareAndSet(false, true)) releaseAppleBackend(datastoreFilePath) },
    )

    // Keychain custody is fixed after construction, but the Simulator fallback for an
    // entitlement-blocked Keychain (errSecMissingEntitlement, -34018) engages lazily on
    // the first blocked key op — so the provider re-reads that flag per access.
    val keychainEngine = engine as? AppleKeychainEncryption
    val protectionInfoSnapshot = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        effectiveLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        custody = if (hasSecureEnclave) {
            "Apple Keychain (Secure Enclave available per-write)"
        } else {
            "Apple Keychain"
        },
        notes = if (hasSecureEnclave) emptyList() else listOf("apple_secure_enclave_absent"),
    )
    val fallbackProtectionInfo = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        effectiveLevel = KSafeProtectionLevel.SOFTWARE,
        custody = "Sandbox file key store (iOS Simulator fallback — Keychain entitlement missing)",
        notes = buildList {
            add("apple_keychain_entitlement_missing")
            if (!hasSecureEnclave) add("apple_secure_enclave_absent")
        },
    )
    return KSafe(
        core = core,
        deviceKeyStorages = deviceKeyStorages,
        protectionInfoProvider = {
            if (keychainEngine?.isSimulatorFallbackActive() == true) fallbackProtectionInfo
            else protectionInfoSnapshot
        },
    )
}

// Non-inline helper kept for external Swift callers that may reference it for warm-up.
@Suppress("unused")
fun obtainAesGcm(): AES.GCM = CryptographyProvider.CryptoKit.get(AES.GCM)
