package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.emptyPreferences
import eu.anifantakis.lib.ksafe.internal.DATASTORE_FILE_SUFFIX
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.AppleKeyCustody
import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.KSAFE_OS_STORE_IDENTITY
import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeAtomicFlag
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeKeyTier
import eu.anifantakis.lib.ksafe.internal.KSafeProtectionNotes
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.SharedBackendRegistry
import eu.anifantakis.lib.ksafe.internal.SharedStoreBackend
import eu.anifantakis.lib.ksafe.internal.asKeyStorage
import eu.anifantakis.lib.ksafe.internal.asProtectionLevel
import eu.anifantakis.lib.ksafe.internal.cleanupOrphanedKeychainEntries
import eu.anifantakis.lib.ksafe.internal.corruptQuarantineName
import eu.anifantakis.lib.ksafe.internal.dataStoreBaseFileName
import eu.anifantakis.lib.ksafe.internal.promoteDefaultToIsolated
import eu.anifantakis.lib.ksafe.internal.requireValidStoreFileName
import eu.anifantakis.lib.ksafe.internal.resolveStoreIdentity
import eu.anifantakis.lib.ksafe.internal.sweepCorruptQuarantineCopies
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import okio.Path.Companion.toPath
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSHomeDirectory
import platform.Foundation.NSString
import platform.Foundation.stringByResolvingSymlinksInPath
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSUserDomainMask
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private const val SERVICE_NAME = KSAFE_OS_STORE_IDENTITY

/** Keychain service name and alias prefix every KSafe store on this device shares. */
@PublishedApi
internal const val KEY_PREFIX = KSAFE_OS_STORE_IDENTITY

@OptIn(ExperimentalForeignApi::class)
private fun isSimulator(): Boolean =
    NSProcessInfo.processInfo.environment["SIMULATOR_UDID"] != null

/**
 * Creates a [KSafe] for Apple targets: DataStore storage under `NSApplicationSupportDirectory`
 * (or [directory]), keys held device-only in the Keychain. [fileName], not [directory], is the
 * key-isolation boundary — same-[fileName] instances share Keychain keys, so keep one per file.
 * Under a [securityPolicy] with a BLOCK action a detected violation throws
 * [SecurityViolationException] here.
 * @param fileName Store name (lowercase letter, then lowercase letters, digits or underscores);
 *   null is the default store. Anything else throws [IllegalArgumentException].
 * @param lazyLoad Skip the background cache load at construction; the first read loads it
 *   instead ([KSafe.getDirect] blocks, [KSafe.get] suspends).
 * @param plaintextCacheTtl Lifetime of a decrypted value under
 *   [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE]; unused by the other policies.
 * @param useSecureEnclave Deprecated: promotes every DEFAULT-tier encrypted write to
 *   HARDWARE_ISOLATED. Request it per write with [KSafeWriteMode.Encrypted] instead.
 * @param directory Absolute directory for the store file; null uses Application Support and also
 *   migrates a legacy Documents-directory file. A custom directory skips the Keychain orphan sweep.
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

/** Test variant: accepts a pre-built [KSafeEncryption] engine in place of the Keychain. */
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

/** Ref-counted per-file DataStore + engine: native DataStore refuses two instances on one file. */
private class AppleBackend(
    val dataStore: DataStore<Preferences>,
    val storage: KSafePlatformStorage,
    scope: CoroutineScope,
) : SharedStoreBackend(scope)

// Kotlin/Native has no Dispatchers.IO, and DataStore's Apple I/O path is non-blocking.
private val appleBackends = SharedBackendRegistry<AppleBackend>(Dispatchers.Default)

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
    requireValidStoreFileName(fileName)
    validateSecurityPolicy(securityPolicy)

    // Probe, don't assume "not the Simulator ⇒ has SE": pre-T2 Intel Macs and VMs have none.
    val hasSecureEnclave: Boolean = !isSimulator() && AppleKeychainEncryption.deviceHasSecureEnclave()

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

    fm.createDirectoryAtPath(
        resolvedDirPath,
        withIntermediateDirectories = true,
        attributes = null,
        error = null,
    )

    val baseFileName = dataStoreBaseFileName(fileName)
    val datastoreFilePath = "$resolvedDirPath/$baseFileName$DATASTORE_FILE_SUFFIX"

    if (directory == null && !fm.fileExistsAtPath(datastoreFilePath)) {
        val docsDirPath: String? = fm.URLForDirectory(
            directory = NSDocumentDirectory,
            inDomain = NSUserDomainMask,
            appropriateForURL = null,
            create = false,
            error = null,
        )?.path
        if (docsDirPath != null) {
            val legacyPath = "$docsDirPath/$baseFileName$DATASTORE_FILE_SUFFIX"
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

    // One identity and one backend per physical store, however its path was spelled. Resolved on
    // the DIRECTORY: resolving a not-yet-existing file path is a no-op, so the identity would
    // change once the file appeared.
    val canonicalDirPath = (resolvedDirPath as NSString).stringByResolvingSymlinksInPath
    val canonicalStorePath = "$canonicalDirPath/$baseFileName$DATASTORE_FILE_SUFFIX"
    val storeIdentity = resolveStoreIdentity(
        canonicalPath = canonicalStorePath,
        // Resolved to the same degree, or a canonical path never prefix-matches a symlinked home.
        canonicalHome = (NSHomeDirectory() as NSString).stringByResolvingSymlinksInPath,
        rawPath = datastoreFilePath,
        rawHome = NSHomeDirectory(),
    )

    val backend = appleBackends.acquire(canonicalStorePath) { scope ->
        val dataStore = PreferenceDataStoreFactory.createWithPath(
            corruptionHandler = ReplaceFileCorruptionHandler {
                runCatching {
                    val dest = corruptQuarantineName(datastoreFilePath)
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
        // Per file, not per instance: its commit relay must reach every sibling's collector.
        AppleBackend(dataStore, DataStoreStorage(dataStore), scope)
    }
    val dataStore: DataStore<Preferences> = backend.dataStore
    val storage = backend.storage

    // One engine per file so co-existing same-file instances don't race master-key creation.
    val engine: KSafeEncryption =
        testEngine ?: backend.engineOrCreate { AppleKeychainEncryption(config = config, serviceName = SERVICE_NAME) }

    // cancel() can run more than once; release the shared backend on the first call only.
    val released = KSafeAtomicFlag(false)

    fun iosKeyAlias(userKey: String): String = KSafeAliasFormat.dotted(fileName, userKey)

    fun iosMasterAlias(requireUnlockedDevice: Boolean): String =
        KSafeAliasFormat.dottedMaster(fileName, requireUnlockedDevice)

    // Handles the legacy "{fileName}_{key}" entry format written by old iOS builds.
    fun iosLegacyEncryptedKey(userKey: String): String =
        fileName?.let { "${it}_$userKey" } ?: KeySafeMetadataManager.legacyEncryptedRawKey(userKey)

    fun iosLegacyEncryptedPrefix(): String =
        fileName?.let { "${it}_" } ?: KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX

    val keychainEngine = engine as? AppleKeychainEncryption

    // Custody of the live key outranks capability inference: a HARDWARE_ISOLATED request can be
    // served by a legacy plain key or the Simulator fallback. Inference covers unclassifiable keys.
    fun resolveKeyTier(protection: KSafeProtection?, engineAlias: String?): KSafeKeyTier {
        if (protection == null) return KSafeKeyTier.SOFTWARE
        when (engineAlias?.let { keychainEngine?.keyCustody(it) }) {
            AppleKeyCustody.SE_WRAPPED -> return KSafeKeyTier.HARDWARE_ISOLATED
            AppleKeyCustody.PLAIN -> return KSafeKeyTier.HARDWARE_BACKED
            AppleKeyCustody.SIMULATOR_FALLBACK -> return KSafeKeyTier.SOFTWARE
            AppleKeyCustody.ABSENT, null -> {}
        }
        return if (protection == KSafeProtection.HARDWARE_ISOLATED && hasSecureEnclave)
            KSafeKeyTier.HARDWARE_ISOLATED
        else KSafeKeyTier.HARDWARE_BACKED
    }

    /** Failures swallowed: a locked device or transient Keychain error must not block startup. */
    suspend fun cleanupOrphanedKeychainEntriesSafe(isUserKeyDirty: (String) -> Boolean) {
        // The Keychain namespace encodes fileName, not directory, so a custom-directory store
        // shares it with a same-fileName sibling whose live keys the sweep would reap.
        if (directory != null) return
        runCatching {
            // Hold the commit mutex across the whole snapshot → classify → delete, or a batch
            // commit mints a key between our snapshot and our deletes and we reap it.
            backend.commitMutex.withLock {
                cleanupOrphanedKeychainEntries(
                    storage = storage,
                    engine = engine,
                    serviceName = SERVICE_NAME,
                    fileName = fileName,
                    legacyEncryptedPrefix = iosLegacyEncryptedPrefix(),
                    seKeyTagPrefix = AppleKeychainEncryption.SE_KEY_TAG_PREFIX,
                    // No user key references a master key; unreserved, DEFAULT data is orphaned.
                    reservedKeyIds = setOf(KSafeReservedKeys.MASTER, KSafeReservedKeys.MASTER_LOCKED),
                    // A write in flight during the sweep commits after our snapshot — don't reap it.
                    isInFlight = isUserKeyDirty,
                )
            }
        }.onFailure { t ->
            if (t is CancellationException) throw t
            println("KSafe: Keychain orphan sweep failed (ignored): ${t.message}")
        }
    }

    val core = KSafeCore(
        // Full store path in the v3 AAD, not just fileName: same-fileName instances in different
        // directories share the Keychain key, so a transplanted ciphertext must fail closed.
        // Home-relative — the iOS container UUID changes on every update.
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
        migrateAccessPolicy = { isUserKeyDirty -> cleanupOrphanedKeychainEntriesSafe(isUserKeyDirty) },
        lazyLoad = lazyLoad,
        keyAlias = ::iosKeyAlias,
        masterAlias = ::iosMasterAlias,
        legacyEncryptedPrefix = iosLegacyEncryptedPrefix(),
        legacyEncryptedKeyFor = ::iosLegacyEncryptedKey,
        modeTransformer = { promoteDefaultToIsolated(it, useSecureEnclave) },
        onCancel = { if (released.compareAndSet(false, true)) appleBackends.release(canonicalStorePath) },
    )
    core.attachSiblings(backend.siblings)

    val protectionInfoSnapshot = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        effectiveLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        custody = if (hasSecureEnclave) {
            "Apple Keychain (Secure Enclave available per-write)"
        } else {
            "Apple Keychain"
        },
        notes = if (hasSecureEnclave) emptyList() else listOf(KSafeProtectionNotes.APPLE_SECURE_ENCLAVE_ABSENT),
    )
    val fallbackProtectionInfo = KSafeProtectionInfo(
        intendedLevel = KSafeProtectionLevel.HARDWARE_BACKED,
        effectiveLevel = KSafeProtectionLevel.SOFTWARE,
        custody = "Sandbox file key store (iOS Simulator fallback — Keychain entitlement missing)",
        notes = buildList {
            add(KSafeProtectionNotes.APPLE_KEYCHAIN_ENTITLEMENT_MISSING)
            if (!hasSecureEnclave) add(KSafeProtectionNotes.APPLE_SECURE_ENCLAVE_ABSENT)
        },
    )
    return KSafe(
        core = core,
        deviceKeyStorages = deviceKeyStorages,
        protectionInfoProvider = {
            // Re-read per access: the Simulator fallback engages on the first blocked Keychain op.
            if (keychainEngine?.isSimulatorFallbackActive() == true) fallbackProtectionInfo
            else protectionInfoSnapshot
        },
        onClearAllCleanup = {
            val fmgr = NSFileManager.defaultManager
            sweepCorruptQuarantineCopies(
                storeFileName = "$baseFileName$DATASTORE_FILE_SUFFIX",
                listNames = {
                    fmgr.contentsOfDirectoryAtPath(resolvedDirPath, error = null)
                        ?.filterIsInstance<String>()
                        .orEmpty()
                },
                delete = { name -> fmgr.removeItemAtPath("$resolvedDirPath/$name", error = null) },
            )
        },
    )
}
