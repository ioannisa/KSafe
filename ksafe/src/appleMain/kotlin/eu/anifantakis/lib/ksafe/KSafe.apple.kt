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

@PublishedApi
internal const val KEY_PREFIX = KSAFE_OS_STORE_IDENTITY

@OptIn(ExperimentalForeignApi::class)
private fun isSimulator(): Boolean =
    NSProcessInfo.processInfo.environment["SIMULATOR_UDID"] != null

/**
 * Creates a [KSafe] for Apple targets (iOS, iPadOS, macOS): DataStore-backed storage under
 * `NSApplicationSupportDirectory` (or [directory]), with encryption keys held device-only in
 * the Keychain and Secure Enclave wrapping available per write.
 *
 * [fileName] is the store's key-isolation boundary: the Keychain key namespace derives from it,
 * NOT from [directory]. Two instances sharing a [fileName] under different [directory] values thus
 * share Keychain keys — keep one `KSafe` per [fileName] and use distinct [fileName]s for
 * independent stores (the startup orphan sweep is skipped for custom-[directory] stores so it can
 * never reap such a sibling's keys).
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
 *  one file and frees it only once the owning scope's Job completes. */
private class AppleBackend(
    val dataStore: DataStore<Preferences>,
    val storage: KSafePlatformStorage,
    scope: CoroutineScope,
) : SharedStoreBackend(scope)

// Dispatchers.Default: Kotlin/Native has no Dispatchers.IO, and DataStore's Apple I/O path is
// non-blocking.
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

    // Probe the SE for real instead of assuming "not the Simulator ⇒ has SE": that was true on
    // iOS but wrong on SE-less Macs (pre-T2 Intel, VMs), where it masked a silent downgrade to a
    // plain Keychain key in protectionInfo/getKeyInfo. Short-circuit on the Simulator (no SE, and
    // the probe there is pointless).
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

    // Best-effort migration of a legacy DataStore file from NSDocumentDirectory (old builds).
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

    // Canonical spelling (symlinks — e.g. /var vs /private/var — and `..`/`.` resolved) so one
    // physical store keeps ONE identity and ONE backend however its `directory` was spelled.
    // Resolved on the DIRECTORY, which was just created above: stringByResolvingSymlinksInPath
    // leaves a non-existent path untouched, so resolving the full file path would be a silent
    // no-op on first launch and the identity/backend key would CHANGE once the file appeared.
    val canonicalDirPath = (resolvedDirPath as NSString).stringByResolvingSymlinksInPath
    val canonicalStorePath = "$canonicalDirPath/$baseFileName$DATASTORE_FILE_SUFFIX"
    val storeIdentity = resolveStoreIdentity(
        canonicalPath = canonicalStorePath,
        // The home is resolved to the SAME degree, or a canonical path could never prefix-match a
        // symlinked home (/var vs /private/var) and the identity would silently stay absolute.
        canonicalHome = (NSHomeDirectory() as NSString).stringByResolvingSymlinksInPath,
        rawPath = datastoreFilePath,
        rawHome = NSHomeDirectory(),
    )

    val backend = appleBackends.acquire(canonicalStorePath) { scope ->
        val dataStore = PreferenceDataStoreFactory.createWithPath(
            // Quarantine a corrupt .preferences_pb and continue from empty instead of throwing
            // CorruptionException on every read; the corrupt bytes are copied aside for recovery.
            corruptionHandler = ReplaceFileCorruptionHandler {
                runCatching {
                    // Fixed name, unlike the JVM targets' timestamped copies: only the newest
                    // corruption is retained here.
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

    // Guards this instance's single backend release (KSafeCore.cancel() is idempotent).
    val released = KSafeAtomicFlag(false)

    fun iosKeyAlias(userKey: String): String = KSafeAliasFormat.dotted(fileName, userKey)

    fun iosMasterAlias(requireUnlockedDevice: Boolean): String =
        KSafeAliasFormat.dottedMaster(fileName, requireUnlockedDevice)

    // Handles the legacy "{fileName}_{key}" entry format written by old iOS builds.
    fun iosLegacyEncryptedKey(userKey: String): String =
        fileName?.let { "${it}_$userKey" } ?: KeySafeMetadataManager.legacyEncryptedRawKey(userKey)

    fun iosLegacyEncryptedPrefix(): String =
        fileName?.let { "${it}_" } ?: KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX

    // Simulator fallback for an entitlement-blocked Keychain (errSecMissingEntitlement, -34018)
    // engages lazily on the first blocked key op, so re-read the flag per access.
    val keychainEngine = engine as? AppleKeychainEncryption

    // Custody-first resolution for getKeyInfo: the live key outranks capability inference,
    // because a HARDWARE_ISOLATED request can be served by a legacy pre-SE plain key (honoured
    // forever) or by the Simulator sandbox fallback. Inference stays as the fallback for keys
    // the engine can't classify (not yet minted, locked device, injected test engine).
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

    /** Orphan sweep with failures swallowed — a locked device or transient Keychain error
     *  must never block startup. */
    suspend fun cleanupOrphanedKeychainEntriesSafe(isUserKeyDirty: (String) -> Boolean) {
        // The Keychain key namespace is KEY_PREFIX.fileName — it does NOT encode `directory` — so a
        // custom-directory instance can share it with a same-fileName sibling in another location.
        // The sweep validates against only THIS store's snapshot, so there it would reap the
        // sibling's live keys as "orphans". Skip it for custom-directory stores (fileName is the
        // isolation boundary; keeping one KSafe per fileName is the supported contract).
        if (directory != null) return
        runCatching {
            // Hold the shared per-store commit mutex across the WHOLE snapshot → classify →
            // delete sequence: a batch commit (whose encrypts mint/reuse keys under it) can
            // then never interleave between our snapshot and our deletes, so a write's key
            // can't be reaped between its encrypt and its commit. The owner-keyed in-flight
            // gate covers writes enqueued but not yet in a batch (dirty is marked at enqueue).
            backend.commitMutex.withLock {
                cleanupOrphanedKeychainEntries(
                    storage = storage,
                    engine = engine,
                    serviceName = SERVICE_NAME,
                    fileName = fileName,
                    legacyEncryptedPrefix = iosLegacyEncryptedPrefix(),
                    seKeyTagPrefix = AppleKeychainEncryption.SE_KEY_TAG_PREFIX,
                    // Shared master keys never appear in the sweep's valid-key set (no single user
                    // key references them); reserve them or the sweep orphans all DEFAULT ciphertext.
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
        // Bind the full store path (directory + fileName), not just fileName, into the v3 AAD —
        // mirroring Android. Two same-fileName instances differing only by `directory` share the
        // same fileName-scoped Keychain key by design, so without this a rotated (v3) ciphertext
        // transplanted between their directories would still decrypt; the path in the AAD makes
        // that fail closed. The Keychain alias stays fileName-scoped (an SE-wrapped/non-exportable
        // key can't be re-aliased without data loss). HOME-RELATIVE, never absolute: the iOS app
        // container UUID changes on every App Store update/restore, so an absolute path would
        // break every rotated entry's AAD after an ordinary update (and the startup orphan sweep
        // would then delete them).
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
        // Only the last live instance on this file cancels the shared scope; guarded to one
        // release because KSafeCore.cancel() is idempotent.
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
