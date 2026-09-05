package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.emptyPreferences
import eu.anifantakis.lib.ksafe.internal.CORRUPT_QUARANTINE_TIMESTAMP_INFIX
import eu.anifantakis.lib.ksafe.internal.DATASTORE_FILE_SUFFIX
import eu.anifantakis.lib.ksafe.internal.FALLBACK_MIGRATED_SUFFIX
import eu.anifantakis.lib.ksafe.internal.FALLBACK_MIGRATION_PENDING_SUFFIX
import eu.anifantakis.lib.ksafe.internal.JSON_FALLBACK_SUFFIX
import eu.anifantakis.lib.ksafe.internal.DataStoreJsonStorage
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeKeyTier
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KSafeProtectionNotes
import eu.anifantakis.lib.ksafe.internal.NAMESPACE_SANITIZE_REGEX
import eu.anifantakis.lib.ksafe.internal.NAMESPACE_TOKEN_MAX_LENGTH
import eu.anifantakis.lib.ksafe.internal.OneShotWarning
import eu.anifantakis.lib.ksafe.internal.SharedBackendRegistry
import eu.anifantakis.lib.ksafe.internal.SharedStoreBackend
import eu.anifantakis.lib.ksafe.internal.asKeyStorage
import eu.anifantakis.lib.ksafe.internal.asProtectionLevel
import eu.anifantakis.lib.ksafe.internal.dataStoreBaseFileName
import eu.anifantakis.lib.ksafe.internal.migrateJsonFallbackToOsBacked
import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.KEY_VAULT_TEMP_SUFFIX
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.keyvault.canonicalJvmNamespaceToken
import eu.anifantakis.lib.ksafe.internal.keyvault.jvmKeyVaultOptedOut
import eu.anifantakis.lib.ksafe.internal.quarantineCorruptStoreFile
import eu.anifantakis.lib.ksafe.internal.requireValidStoreFileName
import eu.anifantakis.lib.ksafe.internal.resolveStoreIdentity
import eu.anifantakis.lib.ksafe.internal.sweepCorruptQuarantineCopies
import eu.anifantakis.lib.ksafe.internal.toStoredMap
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermission
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

// The JVM key vaults persist raw key bytes as Base64 text. The codec itself is KSafeBase64;
// these stay declared here only because the vaults are jvmMain-only.

internal fun encodeBase64(bytes: ByteArray): String = KSafeBase64.encode(bytes)

internal fun decodeBase64(encoded: String): ByteArray = KSafeBase64.decode(encoded)

/**
 * Creates a JVM [KSafe] whose data lives under [baseDir] (default
 * `~/.eu_anifantakis_ksafe`, created if missing with POSIX 0700 permissions).
 *
 * **[fileName] is the key-isolation boundary**, not [baseDir]: the OS key vault (or software
 * fallback) is keyed by an alias scoped to [fileName] (and [KSafeConfig.appNamespace]) only,
 * so two instances that share a [fileName] but differ only in [baseDir] share the same key
 * material — one instance's `clearAll()` deletes the key the other still needs. Give
 * independent stores DISTINCT [fileName]s (or `appNamespace`s). [baseDir] chooses where the
 * data file lives and, once a store has been rotated, is bound into the v3 AAD (so a rotated
 * ciphertext can't be transplanted to a store with a different [baseDir]); it still does not
 * isolate key material.
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

/** Test variant: accepts a pre-built [KSafeEncryption] engine. */
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

/**
 * Per-file shared backend: DataStore refuses two active instances on one file, so live
 * [KSafe] instances sharing a path share one ref-counted backend (last close tears it down).
 */
private class JvmBackend(
    val storage: KSafePlatformStorage,
    scope: CoroutineScope,
    val engine: KSafeEncryption,
    val clearAllCleanup: suspend () -> Unit,
) : SharedStoreBackend(scope)

private val jvmBackends = SharedBackendRegistry<JvmBackend>(Dispatchers.IO)

/**
 * Custody of one JVM key: an OS secret store (DPAPI / Keychain / Secret Service) is sandbox
 * protection, its software fallback is not, and a test-injected engine is assumed to be baseline.
 * There is no device key hardware here, so this never reaches the HARDWARE tiers.
 */
private fun jvmKeyTier(engine: KSafeEncryption, protection: KSafeProtection?): KSafeKeyTier = when {
    protection == null -> KSafeKeyTier.SOFTWARE
    engine is JvmSoftwareEncryption && engine.keyVaultIsOsBacked -> KSafeKeyTier.SANDBOX_PROTECTED
    engine is JvmSoftwareEncryption -> KSafeKeyTier.SOFTWARE
    else -> KSafeKeyTier.SANDBOX_PROTECTED
}

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
    requireValidStoreFileName(fileName)
    validateSecurityPolicy(securityPolicy)

    val resolvedBaseDir: File = baseDir ?: File(
        Paths.get(System.getProperty("user.home")).toFile(),
        ".eu_anifantakis_ksafe",
    )
    if (!resolvedBaseDir.exists()) {
        resolvedBaseDir.mkdirs()
    }
    secureDirectory(resolvedBaseDir)

    val baseFileName = dataStoreBaseFileName(fileName)

    // Same canonicalization as the key vault's namespace (resolveJvmAppNamespace), so one
    // configured token can never split into different data-dir and vault identities.
    val explicitNamespace = canonicalJvmNamespaceToken(config.appNamespace)
    // The pre-3.0.0 directory token (no trim, so whitespace became '_'): when it differs from
    // the canonical one, a shipped app's live data sits in the old subdir — carried forward as
    // the preferred copy source so the canonicalization can't strand it.
    val legacyNamespaceDir: File? = config.appNamespace
        ?.replace(NAMESPACE_SANITIZE_REGEX, "_")
        ?.trimStart('.')
        ?.take(NAMESPACE_TOKEN_MAX_LENGTH)
        ?.takeIf { it.isNotBlank() && it != explicitNamespace }
        ?.let { File(resolvedBaseDir, it) }
    val storageDir: File = if (explicitNamespace != null) {
        val nsDir = File(resolvedBaseDir, explicitNamespace)
        if (!nsDir.exists()) nsDir.mkdirs()
        secureDirectory(nsDir)
        val srcDirs = listOfNotNull(legacyNamespaceDir, resolvedBaseDir)
        degradedCarryForwardSources[degradeMemoKey(nsDir, baseFileName)]
            ?: if (importStoreFilesOnce(srcDirs, nsDir, baseFileName, copy = storeCopy())) nsDir
            else carryForwardSourceForThisSession(srcDirs, baseFileName, nsDir)
    } else {
        // A canonicalized-away token (e.g. whitespace-only) may still have pre-3.0.0 data in
        // its old subdir; surface it at the un-namespaced path it now maps to.
        val srcDirs = listOfNotNull(legacyNamespaceDir)
        degradedCarryForwardSources[degradeMemoKey(resolvedBaseDir, baseFileName)]
            ?: if (srcDirs.isEmpty() ||
                importStoreFilesOnce(srcDirs, resolvedBaseDir, baseFileName, copy = storeCopy())
            ) resolvedBaseDir
            else carryForwardSourceForThisSession(srcDirs, baseFileName, resolvedBaseDir)
    }

    // KSafeCore and the fallback migration must compute identical aliases.
    val keyAlias: (String) -> String = { userKey -> KSafeAliasFormat.colon(fileName, userKey) }
    // JVM has no locked/unlocked split, so both access policies route to the one master.
    val masterAlias: (Boolean) -> String = { _ -> KSafeAliasFormat.colonMaster(fileName) }

    // v3 AAD store identity: the pre-namespace baseDir + fileName, NOT storageDir. Two same-fileName
    // stores in different baseDirs share the fileName-scoped key by design, so binding the baseDir
    // makes a rotated (v3) ciphertext transplanted between them fail closed instead of decrypting.
    // resolvedBaseDir (not storageDir) is deliberate: the appNamespace copy-forward relocates the
    // file into a namespace subdir but resolvedBaseDir is invariant across it, so a v3 entry stays
    // decryptable after that move. Must match all consumers (both engines, migration, KSafeCore).
    // Home-relative, never absolute: a JVM user home can move (renamed account, OS
    // migration, portable install), and an absolute path in the v3 AAD would make every
    // rotated entry fail authentication afterwards. Same defect class as the iOS
    // container-UUID relocation; see KeySafeMetadataManager.stableStoreIdentity.
    // Canonical spelling (symlinks / `..` / a relative baseDir under a changing working
    // directory resolved) so one physical store keeps ONE identity however its baseDir was
    // spelled — two spellings would otherwise bind different AAD and read each other's rotated
    // entries as defaults.
    val identityBaseFile = File(resolvedBaseDir, baseFileName)
    val rawUserHome = System.getProperty("user.home")
    val storeIdentity = resolveStoreIdentity(
        canonicalPath = runCatching { identityBaseFile.canonicalPath }
            .getOrDefault(identityBaseFile.absolutePath),
        // Canonicalized to the same degree as the store path: a symlinked or mounted home
        // (/home -> /System/Volumes/Data/home, /var -> /private/var) would otherwise never
        // prefix-match a canonical path, leaving the identity absolute and the guard inert.
        canonicalHome = rawUserHome?.let { h -> runCatching { File(h).canonicalPath }.getOrDefault(h) },
        rawPath = identityBaseFile.absolutePath,
        rawHome = rawUserHome,
    )

    // Canonical registry key so two spellings of one physical file share the ref-counted backend
    // instead of tripping DataStore's "multiple instances active" fail-fast.
    val backendFile = File(storageDir, baseFileName)
    val backendPath = runCatching { backendFile.canonicalPath }.getOrDefault(backendFile.absolutePath)
    val backend = jvmBackends.acquire(backendPath) { storageScope ->
        createJvmBackend(
            storageScope = storageScope,
            storageDir = storageDir,
            baseFileName = baseFileName,
            config = config,
            testEngine = testEngine,
            keyAlias = keyAlias,
            masterAlias = masterAlias,
            storeIdentity = storeIdentity.canonical,
            fallbackStoreIdentity = storeIdentity.fallback,
            keyNamespace = fileName,
        )
    }

    // Guards this instance's single backend release; KSafeCore.cancel() is idempotent.
    val released = java.util.concurrent.atomic.AtomicBoolean(false)

    val core = KSafeCore(
        // The live v3 AAD authority. MUST be the derived store identity (not fileName) so runtime
        // reads/writes bind the same baseDir-inclusive identity the fallback migration uses —
        // otherwise a v3 entry written here would fail the migration's decrypt and be dropped.
        storeIdentity = storeIdentity.canonical,
        fallbackStoreIdentity = storeIdentity.fallback,
        keyNamespace = fileName,
        commitMutex = backend.commitMutex,
        storage = backend.storage,
        engineProvider = { backend.engine },
        config = config,
        memoryPolicy = memoryPolicy,
        plaintextCacheTtl = plaintextCacheTtl,
        resolveKeyStorage = { _, protection, _ -> jvmKeyTier(backend.engine, protection).asKeyStorage() },
        resolveKeyLevel = { _, protection, _ -> jvmKeyTier(backend.engine, protection).asProtectionLevel() },
        lazyLoad = lazyLoad,
        keyAlias = keyAlias,
        masterAlias = masterAlias,
        onCancel = { if (released.compareAndSet(false, true)) jvmBackends.release(backendPath) },
    )
    core.attachSiblings(backend.siblings)

    return KSafe(
        core = core,
        deviceKeyStorages = setOf(KSafeKeyStorage.SOFTWARE),
        // Recomputed per access so a runtime degrade shows up in `protectionInfo`.
        protectionInfoProvider = { jvmProtectionInfo(backend.engine) },
        onClearAllCleanup = backend.clearAllCleanup,
    )
}

/**
 * Publish order, not merely the file list: whatever a published file makes the next launch DO must
 * already be in place when that file appears. The fallback JSON is the trigger — its presence alone
 * re-runs the drain — so it goes last, after the two markers that gate the drain, the key sidecar
 * that decrypts it, and the store file whose newer values it must not roll back.
 */
private val storeCohortSuffixes = listOf(
    JSON_FALLBACK_SUFFIX + FALLBACK_MIGRATED_SUFFIX,
    JSON_FALLBACK_SUFFIX + FALLBACK_MIGRATION_PENDING_SUFFIX,
    ".ksafe-keys.json",
    DATASTORE_FILE_SUFFIX,
    JSON_FALLBACK_SUFFIX,
)

/** androidx.datastore's write scratch file: `File(file.absolutePath + ".tmp")` in `FileStorage`. */
private const val DATASTORE_SCRATCH_SUFFIX: String = ".tmp"

private const val REWRITE_WINDOW_SAMPLES: Int = 10
private const val REWRITE_WINDOW_SAMPLE_MS: Long = 10

/**
 * DataStore's JVM rewrite is unlink-then-rename: a live store file is briefly absent while its
 * scratch sibling exists, and a single `exists()` sample there would read as "no data here".
 */
private fun cohortFilePresent(file: File): Boolean {
    if (file.exists()) return true
    val scratch = File(file.path + DATASTORE_SCRATCH_SUFFIX)
    repeat(REWRITE_WINDOW_SAMPLES) {
        if (!scratch.exists()) return false
        try {
            Thread.sleep(REWRITE_WINDOW_SAMPLE_MS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return file.exists()
        }
        if (file.exists()) return true
    }
    return false
}

/** The single directory a carry-forward publishes from: the first of [srcDirs] holding any cohort file. */
internal fun selectCopyForwardSource(srcDirs: List<File>, baseFileName: String): File? =
    srcDirs.firstOrNull { dir -> storeCohortSuffixes.any { cohortFilePresent(File(dir, baseFileName + it)) } }

/**
 * Copies one store's on-disk files into [dstDir] (existing destinations kept). Copy, never
 * move: a move would steal another app's shared un-namespaced file. The whole cohort comes
 * from ONE source directory — the first of [srcDirs] holding any cohort file — because
 * per-file source selection could pair a data file with a different historical store's key
 * sidecar, or carry a foreign `.migrated`/`.migration-pending` marker whose mtime defeats
 * the fallback-migration gate. Each file is staged to a temp name and published by rename
 * only after every copy succeeded, so a failure mid-cohort leaves no final name occupied (a
 * truncated destination would count as "exists" and block the retry forever) and the next
 * launch retries the whole cohort. Each copy keeps the SOURCE mtime: `copyTo` stamps copy
 * time, which would make the copied `.migrated` marker at least as new as the copied
 * fallback JSON and deterministically skip a genuinely-newer second fallback period's
 * migration, stranding its values. The `.migration-pending` marker is carried too: without
 * it a namespaced first launch after an un-namespaced transient migration failure reverts to
 * "fallback wins" and can overwrite the newer OS-backed writes the copied `.preferences_pb`
 * holds. Returns true once the cohort is fully published (or there was nothing to copy), false
 * when a copy or rename failed and the next launch must retry.
 */
internal fun copyStoreFilesForward(
    srcDirs: List<File>,
    dstDir: File,
    baseFileName: String,
    rename: (File, File) -> Boolean = { tmp, dst -> tmp.renameTo(dst) },
    copy: (File, File) -> Unit = { src, dst -> src.copyTo(dst, overwrite = true) },
): Boolean {
    val srcDir = selectCopyForwardSource(srcDirs, baseFileName) ?: return true
    val staged = ArrayList<Pair<File, File>>()
    for (suffix in storeCohortSuffixes) {
        val dst = File(dstDir, baseFileName + suffix)
        if (cohortFilePresent(dst)) continue
        val src = File(srcDir, baseFileName + suffix).takeIf { cohortFilePresent(it) } ?: continue
        val tmp = File(dstDir, dst.name + ".fwd-tmp")
        try {
            copy(src, tmp)
            val srcMtime = src.lastModified()
            if (srcMtime > 0) tmp.setLastModified(srcMtime)
            staged += tmp to dst
        } catch (_: Throwable) {
            runCatching { tmp.delete() }
            staged.forEach { (t, _) -> runCatching { t.delete() } }
            return false
        }
    }
    for ((index, entry) in staged.withIndex()) {
        val (tmp, dst) = entry
        if (rename(tmp, dst)) continue
        // Same-directory renames fail rarely (an indexer's file lock), but skipping just the
        // failed one would publish a later file without the earlier one it depends on — the
        // whole point of the order above. Dropping the rest instead leaves those names absent
        // for the next launch to re-copy; what is published stays a valid prefix of the cohort.
        staged.drop(index).forEach { (rest, _) -> runCatching { rest.delete() } }
        return false
    }
    return true
}

/** Named outside clearAll()'s residue sweep: no `<base>.ksafe` prefix, no `.fwd-tmp` suffix. */
internal const val NAMESPACE_IMPORT_MARKER_SUFFIX: String = ".ns-imported"

/** Test seam: injects a copy fault into the factory's carry-forward. `null` in production. */
internal var copyForwardCopyForTest: ((File, File) -> Unit)? = null

private fun storeCopy(): (File, File) -> Unit =
    copyForwardCopyForTest ?: { src, dst -> src.copyTo(dst, overwrite = true) }

/**
 * One-shot carry-forward: a marker written after a complete publish keeps a later clearAll() from
 * re-arming it. Returns true when [dstDir] holds the cohort — already imported, nothing to import,
 * or just published — and false when a source cohort exists and the publish failed.
 * Finding nothing is deliberately NOT marked: it may be a store caught mid-rewrite, and a marker
 * written on that reading would strand the un-namespaced data forever.
 */
internal fun importStoreFilesOnce(
    srcDirs: List<File>,
    dstDir: File,
    baseFileName: String,
    rename: (File, File) -> Boolean = { tmp, dst -> tmp.renameTo(dst) },
    copy: (File, File) -> Unit = { src, dst -> src.copyTo(dst, overwrite = true) },
): Boolean {
    val marker = File(dstDir, baseFileName + NAMESPACE_IMPORT_MARKER_SUFFIX)
    if (marker.exists()) return true
    if (!copyStoreFilesForward(srcDirs, dstDir, baseFileName, rename, copy)) return false
    val published = storeCohortSuffixes.any { cohortFilePresent(File(dstDir, baseFileName + it)) }
    if (published) runCatching { marker.createNewFile() }
    return true
}

/**
 * Destinations this process has already degraded, and the source each degraded to. Lives until
 * process exit: a second construction on a degraded store joins it instead of re-attempting the
 * copy, which would otherwise snapshot a store file the first instance is actively writing and
 * then publish the marker that strands its writes.
 */
private val degradedCarryForwardSources = java.util.concurrent.ConcurrentHashMap<String, File>()

private fun degradeMemoKey(dstDir: File, baseFileName: String): String =
    runCatching { dstDir.canonicalPath }.getOrDefault(dstDir.absolutePath) + "|" + baseFileName

/** Test seam: forgets the degrade memo, modelling a process restart. */
internal fun clearCarryForwardDegradeMemoForTest() = degradedCarryForwardSources.clear()

/**
 * A failed carry-forward must not promote the empty destination to authoritative: a store file
 * created there would be skipped by the name-keyed retry forever, so this session runs from the
 * source. For the duration of the degrade this session reads, writes and `clearAll()`s that
 * shared source store.
 */
private fun carryForwardSourceForThisSession(
    srcDirs: List<File>,
    baseFileName: String,
    dstDir: File,
): File {
    val src = selectCopyForwardSource(srcDirs, baseFileName) ?: return dstDir
    degradedCarryForwardSources[degradeMemoKey(dstDir, baseFileName)] = src
    System.err.println(
        "KSafe Warning: the store carry-forward into '${dstDir.absolutePath}' failed; " +
            "running from '${src.absolutePath}' until a later launch's carry-forward succeeds; " +
            "reads, writes and clearAll() act on that shared store until then."
    )
    return src
}

/**
 * Builds the storage + engine + clearAll-cleanup for one file, selecting the DataStore backend
 * or the no-`sun.misc.Unsafe` JSON-file fallback and running the one-time JSON→OS-backed
 * migration. Invoked once per file path, under that path's lock.
 */
private fun createJvmBackend(
    storageScope: CoroutineScope,
    storageDir: File,
    baseFileName: String,
    config: KSafeConfig,
    testEngine: KSafeEncryption?,
    keyAlias: (String) -> String,
    masterAlias: (Boolean) -> String,
    storeIdentity: String,
    fallbackStoreIdentity: String,
    keyNamespace: String?,
): JvmBackend {
    val storage: KSafePlatformStorage
    val engine: KSafeEncryption
    val clearAllCleanup: suspend () -> Unit

    if (testEngine == null && !isSunMiscUnsafePresent()) {
        // `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is missing (typically a jlink-trimmed
        // Compose Desktop distributable); DataStore's protobuf hard-requires it and would crash,
        // so persist to a software-encrypted JSON file instead (no OS-backed keys, no data loss).
        warnUsingJsonFileFallbackOnce()
        val jsonFile = File(storageDir, "$baseFileName$JSON_FALLBACK_SUFFIX")
        val keysFile = File(storageDir, "$baseFileName.ksafe-keys.json")
        storage = DataStoreJsonStorage(jsonFile, storageScope)
        engine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
        )
        clearAllCleanup = {
            // The live jsonFile (ciphertext) and keysFile (plaintext AES keys) are wiped on the
            // write consumer by core.clearAll(); a raw File.delete() on this caller thread would
            // race a concurrent put()'s consumer batch and drop an acknowledged write, so they
            // are excluded here and only stale archive/quarantine residue is swept.
            deleteResidualFallbackFiles(storageDir, baseFileName, exclude = setOf(jsonFile.name, keysFile.name))
        }
    } else {
        val datastoreFile = File(storageDir, "$baseFileName$DATASTORE_FILE_SUFFIX")
        val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
            // A corrupt .preferences_pb otherwise throws CorruptionException on every read forever;
            // quarantine the unreadable file (copy aside for recovery) and continue from empty.
            corruptionHandler = ReplaceFileCorruptionHandler {
                quarantineCorruptStoreFile(datastoreFile)
                emptyPreferences()
            },
            scope = storageScope,
            produceFile = { datastoreFile }
        )
        storage = DataStoreStorage(dataStore)
        engine = testEngine ?: JvmSoftwareEncryption(config, dataStore)
        clearAllCleanup = {
            // The DataStore file is NOT deleted here: core.clearAll() already emptied it on the
            // write consumer, and a raw File.delete() on this caller thread would race a concurrent
            // consumer batch (e.g. a key mint during rotation) and strand an in-RAM-only key.
            // deleteResidualFallbackFiles below only matches the `<base>.ksafe` prefix, so the
            // datastore file's own quarantine copies need this sweep.
            sweepCorruptQuarantineCopies(datastoreFile)
            // A prior JSON-fallback period may have left recoverable residue even on the
            // OS-backed path; clearAll() must wipe it too.
            deleteResidualFallbackFiles(storageDir, baseFileName)
        }

        // One-time forward migration: re-encrypt any no-`Unsafe` JSON-fallback data under the
        // OS-backed key so it carries forward instead of appearing empty. Fallback values win
        // over the target, except keys written to the target since a failed prior attempt
        // (tracked via `.migration-pending`). Skipped for test engines.
        if (testEngine == null) {
            val jsonFallback = File(storageDir, "$baseFileName$JSON_FALLBACK_SUFFIX")
            val migrationMarker =
                File(storageDir, "$baseFileName$JSON_FALLBACK_SUFFIX$FALLBACK_MIGRATED_SUFFIX")
            // Compare mtimes, not just `!marker.exists()`: the `.migrated` archive is permanent, so
            // gating on existence alone would skip a second modules-off→on fallback period forever.
            // A fallback file newer than the marker is fresh data to migrate; older is stale residue.
            val needsMigration = jsonFallback.exists() &&
                (!migrationMarker.exists() || jsonFallback.lastModified() > migrationMarker.lastModified())
            if (needsMigration) {
                migrateJsonFallbackToOsBacked(
                    config = config,
                    jsonFallback = jsonFallback,
                    keysFallback = File(storageDir, "$baseFileName.ksafe-keys.json"),
                    target = storage,
                    targetEngine = engine,
                    keyAlias = keyAlias,
                    masterAlias = masterAlias,
                    storeIdentity = storeIdentity,
                    fallbackStoreIdentity = fallbackStoreIdentity,
                    keyNamespace = keyNamespace,
                )
            }
        }
    }

    return JvmBackend(storage, storageScope, engine, clearAllCleanup)
}

/**
 * Deletes residual JVM-fallback files that still hold recoverable secrets — `*.migrated` migration
 * archives (plaintext AES keys + the ciphertext they decrypt), `*.corrupt-<ts>` quarantine copies,
 * and any live `<base>.ksafe.json` / `<base>.ksafe-keys.json`. clearAll() promises a full wipe;
 * leaving any of these would let anyone with file access decrypt pre-migration secrets offline.
 * Matched by the `<baseFileName>.ksafe` prefix so a sibling safe's files aren't touched.
 */
private fun deleteResidualFallbackFiles(
    storageDir: File,
    baseFileName: String,
    // On the JSON-fallback backend the two live files are the active store, wiped on the write
    // consumer by core.clearAll(); deleting them here (caller thread) would race a concurrent
    // write, so they are excluded. On the OS-backed backend they are stale residue, swept normally.
    exclude: Set<String> = emptySet(),
) {
    runCatching {
        val prefix = "$baseFileName.ksafe"
        val liveJson = "$baseFileName$JSON_FALLBACK_SUFFIX"
        val liveKeys = "$baseFileName.ksafe-keys.json"
        storageDir.listFiles()?.forEach { f ->
            val n = f.name
            if (n in exclude) return@forEach
            // Crash-leftover copy-forward staging temps still hold recoverable data (the
            // keys temp is a full plaintext AES key map); matched on `<base>.` so a
            // longer-named sibling safe's temps aren't touched.
            if (n.endsWith(".fwd-tmp") && n.startsWith("$baseFileName.")) {
                runCatching { f.delete() }
                return@forEach
            }
            if (n.startsWith(prefix) &&
                (n == liveJson || n == liveKeys ||
                    // Crash-leftover FileKeyVault.write() temp files: each a full plaintext copy
                    // of the AES key map (`<base>.ksafe-keys.json<random>.tmp`).
                    (n.startsWith(liveKeys) && n.endsWith(KEY_VAULT_TEMP_SUFFIX)) ||
                    n.endsWith(FALLBACK_MIGRATED_SUFFIX) ||
                    n.endsWith(FALLBACK_MIGRATION_PENDING_SUFFIX) ||
                    n.contains(CORRUPT_QUARANTINE_TIMESTAMP_INFIX))
            ) {
                runCatching { f.delete() }
            }
        }
    }
}

/**
 * Builds [KSafeProtectionInfo] from the active vault descriptor. A test-injected engine has no
 * vault to introspect, so it reports the engine class name as custody at the intended baseline.
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
    val optOut = jvmKeyVaultOptedOut()
    return KSafeProtectionInfo(
        intendedLevel = intended,
        effectiveLevel = if (osBacked) KSafeProtectionLevel.SANDBOX_PROTECTED else KSafeProtectionLevel.SOFTWARE,
        custody = engine.keyVaultName,
        notes = when {
            osBacked -> emptyList()
            optOut   -> listOf(KSafeProtectionNotes.JVM_USER_OPTED_OUT)
            // An OS vault exists but failed its self-test: KSafe refuses to mint keys to protect
            // the real OS key, so encrypted ops THROW. Non-operational — a distinct note from the
            // "no OS vault, software works" case below so isEncryptionOperational can tell them apart.
            engine.osVaultUnavailable -> listOf(KSafeProtectionNotes.JVM_OS_VAULT_DEGRADED)
            else     -> listOf(KSafeProtectionNotes.JVM_OS_VAULT_UNAVAILABLE)
        },
    )
}

/**
 * True iff `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is on the runtime. Absent (a
 * jlink-trimmed runtime) selects [DataStoreJsonStorage] rather than crashing in DataStore's protobuf.
 */
private fun isSunMiscUnsafePresent(): Boolean = try {
    Class.forName("sun.misc.Unsafe", false, KSafe::class.java.classLoader)
    true
} catch (_: Throwable) {
    false
}

private val jsonFallbackWarning = OneShotWarning()

private fun warnUsingJsonFileFallbackOnce() {
    jsonFallbackWarning.warn {
        "KSafe NOTICE: `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is " +
            "missing — using the JSON-file storage fallback. Data still " +
            "persists (software-encrypted in a plain JSON file), but without " +
            "the Jetpack DataStore backend or OS-backed key custody. This is " +
            "usually a Compose Desktop release distributable whose jlink " +
            "runtime was trimmed; add `modules(\"jdk.unsupported\")` to your " +
            "`compose.desktop.application.nativeDistributions` block to restore " +
            "DataStore + the OS keyvault (add `\"java.management\"` too if you " +
            "use a non-default KSafeSecurityPolicy). See docs/JVM_PROTECTION.md."
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

// Whitebox test hooks: KSafe is in commonMain (no platform members), so these are
// platform-source-set extensions in the same package.

@PublishedApi
internal val KSafe.dataStore: DataStore<Preferences>
    get() = (core.storage as DataStoreStorage).dataStore

@PublishedApi
internal val KSafe.engine: KSafeEncryption
    get() = core.engine

@PublishedApi
internal fun KSafe.updateCache(prefs: Preferences) {
    val out = toStoredMap(prefs)
    // core.updateCache is suspend for web's async decrypt; JVM crypto is blocking, so runBlocking is fine.
    kotlinx.coroutines.runBlocking { core.updateCache(out) }
}
