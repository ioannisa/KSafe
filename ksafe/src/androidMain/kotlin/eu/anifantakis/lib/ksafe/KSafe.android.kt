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
import eu.anifantakis.lib.ksafe.internal.ANDROID_KEYSTORE_PROVIDER
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.BACKEND_TEARDOWN_TIMEOUT_MS
import eu.anifantakis.lib.ksafe.internal.DATASTORE_FILE_SUFFIX
import eu.anifantakis.lib.ksafe.internal.DataStoreDekStore
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KSAFE_OS_STORE_IDENTITY
import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeKeyTier
import eu.anifantakis.lib.ksafe.internal.KSafeProtectionNotes
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.SharedBackendRegistry
import eu.anifantakis.lib.ksafe.internal.SharedStoreBackend
import eu.anifantakis.lib.ksafe.internal.asKeyStorage
import eu.anifantakis.lib.ksafe.internal.asProtectionLevel
import eu.anifantakis.lib.ksafe.internal.dataStoreBaseFileName
import eu.anifantakis.lib.ksafe.internal.promoteDefaultToIsolated
import eu.anifantakis.lib.ksafe.internal.quarantineCorruptStoreFile
import eu.anifantakis.lib.ksafe.internal.requireValidStoreFileName
import eu.anifantakis.lib.ksafe.internal.resolveStoreIdentity
import eu.anifantakis.lib.ksafe.internal.sweepCorruptQuarantineCopies
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** Leading segment of every Android Keystore alias KSafe creates, so its keys can be told apart
 *  from the app's own. */
const val KEY_ALIAS_PREFIX: String = KSAFE_OS_STORE_IDENTITY

// One DataStore and one engine per file, or sibling DEK caches diverge from the on-disk DEK slot.
private class AndroidBackend(
    val dataStore: DataStore<Preferences>,
    val storage: KSafePlatformStorage,
    scope: CoroutineScope,
) : SharedStoreBackend(scope)

private val backends = SharedBackendRegistry<AndroidBackend>(Dispatchers.IO) { path ->
    println(
        "KSafe: prior DataStore for '$path' had not finished tearing down within " +
            "${BACKEND_TEARDOWN_TIMEOUT_MS}ms; the first access may transiently fail " +
            "(\"multiple DataStores active for the same file\") until it does, then self-recovers."
    )
}

// Safe to cache: a minted Keystore key never changes security level — rotation mints new aliases.
private val strongBoxByAlias = ConcurrentHashMap<String, Boolean>()

// Key creation can silently fall back to the TEE, so the requested tier alone over-reports.
// Only answerable on API 31+; null means indeterminate and callers keep the capability inference.
private fun isKeyActuallyStrongBox(alias: String?): Boolean? {
    if (alias == null || Build.VERSION.SDK_INT < 31) return null
    strongBoxByAlias[alias]?.let { return it }
    return try {
        val keyStore = java.security.KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
        val key = keyStore.getKey(alias, null) as? javax.crypto.SecretKey ?: return null
        val info = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE_PROVIDER)
            .getKeySpec(key, android.security.keystore.KeyInfo::class.java)
            as android.security.keystore.KeyInfo
        val strongBox =
            info.securityLevel == android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX
        strongBoxByAlias[alias] = strongBox
        strongBox
    } catch (_: Throwable) {
        null
    }
}

/**
 * Creates an Android [KSafe]: a DataStore file in the app-private directory (or [baseDir]) with
 * keys held in the Android Keystore. Returns at once; the file loads in the background unless
 * [lazyLoad] is set. Instances on the same file share one backend, so keep one per file and call
 * [KSafe.close] only when re-creating it mid-process.
 *
 * @param context Any context; only the application context is retained.
 * @param fileName Store name (a lowercase letter, then lowercase letters, digits or underscores);
 *   null for the default store. Also the key-isolation boundary: Keystore aliases are scoped by
 *   [fileName] alone, so two instances differing only in [baseDir] share key material and one's
 *   [KSafe.clearAll] deletes the key the other still needs.
 * @param lazyLoad Skips the background preload; the first read then blocks once to load the file.
 * @param memoryPolicy How decrypted values are held in RAM; see [KSafeMemoryPolicy].
 * @param config AES key size, serializer, default unlock policy and key rotation; see [KSafeConfig].
 * @param securityPolicy Rooted-device, debugger, debug-build and emulator checks, run once here.
 * @param plaintextCacheTtl Lifetime of the plaintext side cache; only used under
 *   [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE].
 * @param useStrongBox Deprecated: promotes every DEFAULT encrypted write to
 *   [KSafeEncryptedProtection.HARDWARE_ISOLATED]. Request it per write, or via [KSafeHardwareIsolated].
 * @param baseDir Directory for the `.preferences_pb` file, created if missing. Null (recommended)
 *   uses the sandboxed app-private path; a custom directory is not sandbox-isolated, so never point
 *   it at external storage.
 * @throws IllegalArgumentException if [fileName] is malformed.
 * @throws SecurityViolationException if a [securityPolicy] check set to [SecurityAction.BLOCK] fires.
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

/** Test variant of [KSafe]: uses [testEngine] in place of the Android Keystore engine. */
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
    requireValidStoreFileName(fileName)

    SecurityChecker.applicationContext = context.applicationContext

    validateSecurityPolicy(securityPolicy)

    val hasStrongBox: Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    val deviceKeyStorages: Set<KSafeKeyStorage> = buildSet {
        add(KSafeKeyStorage.HARDWARE_BACKED)
        if (hasStrongBox) add(KSafeKeyStorage.HARDWARE_ISOLATED)
    }

    val baseFileName = dataStoreBaseFileName(fileName)

    val datastoreFile: File = if (baseDir != null) {
        if (!baseDir.exists()) baseDir.mkdirs()
        File(baseDir, "$baseFileName$DATASTORE_FILE_SUFFIX")
    } else {
        context.preferencesDataStoreFile(baseFileName)
    }

    val datastorePath = datastoreFile.absolutePath
    // Canonical spelling, so two spellings of one file keep one identity and one DataStore.
    val backendKey = runCatching { datastoreFile.canonicalPath }.getOrDefault(datastorePath)
    val rawDataDir = context.applicationInfo.dataDir
    // Home-relative identity, never the raw absolute path: adoptable storage relocates the data
    // dir while the Keystore keys survive, so every rotated entry's AAD would fail after a move.
    val storeIdentity = resolveStoreIdentity(
        canonicalPath = backendKey,
        // /data/user/0/<pkg> is a symlink to /data/data/<pkg>: a canonical path never
        // prefix-matches the raw dataDir.
        canonicalHome = runCatching { File(rawDataDir).canonicalPath }.getOrDefault(rawDataDir),
        rawPath = datastorePath,
        rawHome = rawDataDir,
    )
    val backend = backends.acquire(backendKey) { scope ->
        val dataStore = PreferenceDataStoreFactory.create(
            // Quarantine a corrupt file and continue from empty, instead of throwing on every read.
            corruptionHandler = ReplaceFileCorruptionHandler {
                quarantineCorruptStoreFile(datastoreFile)
                emptyPreferences()
            },
            scope = scope,
            produceFile = { datastoreFile },
        )
        // Per file, not per instance: its commit relay must reach every sibling's collector.
        AndroidBackend(dataStore, DataStoreStorage(dataStore), scope)
    }

    // Must match masterAlias(false) below: the un-suffixed relaxed master is the alias existing
    // installs already hold, so they upgrade with no migration.
    val storage = backend.storage
    val relaxedMasterBaseAlias = KSafeAliasFormat.dotted(fileName, KSafeReservedKeys.MASTER)
    val engine: KSafeEncryption = testEngine
        ?: backend.engineOrCreate {
            AndroidKeystoreEncryption(
                config = config,
                dekStore = DataStoreDekStore(storage, baseAlias = relaxedMasterBaseAlias),
            )
        }

    // A `false` probe means the key verifiably sits in the TEE; `true`/`null` keep the inference.
    fun resolveKeyTier(protection: KSafeProtection?, engineAlias: String?): KSafeKeyTier {
        if (protection == null) return KSafeKeyTier.SOFTWARE
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasStrongBox &&
            isKeyActuallyStrongBox(engineAlias) != false
        ) KSafeKeyTier.HARDWARE_ISOLATED
        else KSafeKeyTier.HARDWARE_BACKED
    }

    val released = java.util.concurrent.atomic.AtomicBoolean(false)

    val core = KSafeCore(
        // v3 AAD binds the FULL store path, not just fileName: instances sharing a fileName but
        // differing in baseDir share key material, so the path binding isolates their ciphertexts.
        // The KEK alias stays fileName-scoped — a Keystore key cannot move alias without data loss.
        storeIdentity = storeIdentity.canonical,
        fallbackStoreIdentity = storeIdentity.fallback,
        keyNamespace = fileName,
        commitMutex = backend.commitMutex,
        storage = storage,
        engineProvider = { engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = { _, protection, engineAlias -> resolveKeyTier(protection, engineAlias).asKeyStorage() },
        resolveKeyLevel = { _, protection, engineAlias -> resolveKeyTier(protection, engineAlias).asProtectionLevel() },
        lazyLoad = lazyLoad,
        keyAlias = { userKey -> KSafeAliasFormat.dotted(fileName, userKey) },
        masterAlias = { requireUnlockedDevice -> KSafeAliasFormat.dottedMaster(fileName, requireUnlockedDevice) },
        modeTransformer = { promoteDefaultToIsolated(it, useStrongBox) },
        onCancel = {
            if (released.compareAndSet(false, true)) backends.release(backendKey)
        },
    )
    core.attachSiblings(backend.siblings)

    val protectionInfoSnapshot = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        effectiveLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        custody = if (hasStrongBox) {
            "Android Keystore (TEE; StrongBox available per-write; relaxed DEFAULT values use a TEE-wrapped AES key held in memory)"
        } else {
            "Android Keystore (TEE; relaxed DEFAULT values use a TEE-wrapped AES key held in memory)"
        },
        notes = buildList {
            if (!hasStrongBox) add(KSafeProtectionNotes.ANDROID_STRONGBOX_ABSENT)
            add(KSafeProtectionNotes.ANDROID_RELAXED_DEFAULT_USES_SOFTWARE_DEK)
        },
    )
    return KSafe(
        core = core,
        deviceKeyStorages = deviceKeyStorages,
        protectionInfoProvider = { protectionInfoSnapshot },
        onClearAllCleanup = {
            // The quarantine copies also hold the wrapped DEK, not just ciphertext.
            sweepCorruptQuarantineCopies(datastoreFile)
        },
    )
}
