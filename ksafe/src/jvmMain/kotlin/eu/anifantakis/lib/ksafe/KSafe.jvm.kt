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

internal fun encodeBase64(bytes: ByteArray): String = KSafeBase64.encode(bytes)

internal fun decodeBase64(encoded: String): ByteArray = KSafeBase64.decode(encoded)

/**
 * Creates a JVM [KSafe] storing data under [baseDir] (default `~/.eu_anifantakis_ksafe`, 0700).
 *
 * Key material is scoped to [fileName] (and [KSafeConfig.appNamespace]), not [baseDir]: two
 * instances sharing a [fileName] share one key, so give independent stores distinct names.
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

/** DataStore refuses two active instances on one file, so instances sharing a path share a
 *  ref-counted backend. */
private class JvmBackend(
    val storage: KSafePlatformStorage,
    scope: CoroutineScope,
    val engine: KSafeEncryption,
    val clearAllCleanup: suspend () -> Unit,
) : SharedStoreBackend(scope)

private val jvmBackends = SharedBackendRegistry<JvmBackend>(Dispatchers.IO)

/** An OS secret store is sandbox protection, its software fallback is not; the JVM has no key
 *  hardware, so this never reaches the HARDWARE tiers. */
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

    // Must match the key vault's canonicalization, or one token splits into two identities.
    val explicitNamespace = canonicalJvmNamespaceToken(config.appNamespace)
    // The older, untrimmed token: a shipped app's data may sit in that subdir, so it is preferred.
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
        // A canonicalized-away token may still have data under its old subdir.
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

    // v3 AAD identity: resolvedBaseDir + fileName, never storageDir — the namespace copy-forward
    // moves the file but resolvedBaseDir survives it. Home-relative and canonical, or a moved home
    // or a second spelling breaks authentication. Every consumer must derive it the same way.
    val identityBaseFile = File(resolvedBaseDir, baseFileName)
    val rawUserHome = System.getProperty("user.home")
    val storeIdentity = resolveStoreIdentity(
        canonicalPath = runCatching { identityBaseFile.canonicalPath }
            .getOrDefault(identityBaseFile.absolutePath),
        // A symlinked home (/var -> /private/var) never prefix-matches a canonical store path.
        canonicalHome = rawUserHome?.let { h -> runCatching { File(h).canonicalPath }.getOrDefault(h) },
        rawPath = identityBaseFile.absolutePath,
        rawHome = rawUserHome,
    )

    // Canonical key, or two spellings of one file trip DataStore's multiple-instances fail-fast.
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

    val released = java.util.concurrent.atomic.AtomicBoolean(false)

    val core = KSafeCore(
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

/** Publish order: the fallback JSON's presence alone re-runs the drain, so it goes last — after
 *  the markers that gate it, the key sidecar, and the store file. */
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

/** DataStore's JVM rewrite is unlink-then-rename: a live store file is briefly absent while its
 *  scratch sibling exists, and one `exists()` sample there reads as "no data here". */
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

internal fun selectCopyForwardSource(srcDirs: List<File>, baseFileName: String): File? =
    srcDirs.firstOrNull { dir -> storeCohortSuffixes.any { cohortFilePresent(File(dir, baseFileName + it)) } }

/** Copies one store's cohort into [dstDir] from ONE source dir — a mixed cohort would pair a
 *  data file with another store's key sidecar. Copy, never move: the source may be shared. */
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
            // Keep the source mtime, or the copied `.migrated` marker skips a newer fallback's migration.
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
        // Skipping just the failed one would publish a later file without the earlier one it
        // depends on; dropping the rest keeps what is published a valid prefix of the cohort.
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

/** One-shot carry-forward gated by a marker, so a later clearAll() cannot re-arm it. Finding
 *  nothing is NOT marked: a store caught mid-rewrite would be stranded forever. */
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

/** Destinations this process already degraded, and the source each runs from. Re-attempting the
 *  copy would snapshot a file the first instance is writing, then mark it done. */
private val degradedCarryForwardSources = java.util.concurrent.ConcurrentHashMap<String, File>()

private fun degradeMemoKey(dstDir: File, baseFileName: String): String =
    runCatching { dstDir.canonicalPath }.getOrDefault(dstDir.absolutePath) + "|" + baseFileName

internal fun clearCarryForwardDegradeMemoForTest() = degradedCarryForwardSources.clear()

/** A failed carry-forward must not promote the empty destination — the name-keyed retry would skip
 *  it forever — so this session reads, writes and `clearAll()`s the source store. */
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

/** Builds the storage, engine and clearAll cleanup for one file, choosing the DataStore backend
 *  or the no-`sun.misc.Unsafe` JSON fallback. Once per file path, under that path's lock. */
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
        // `sun.misc.Unsafe` is missing (typically a jlink-trimmed distributable) and DataStore's
        // protobuf hard-requires it, so persist to a software-encrypted JSON file instead.
        warnUsingJsonFileFallbackOnce()
        val jsonFile = File(storageDir, "$baseFileName$JSON_FALLBACK_SUFFIX")
        val keysFile = File(storageDir, "$baseFileName.ksafe-keys.json")
        storage = DataStoreJsonStorage(jsonFile, storageScope)
        engine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
        )
        clearAllCleanup = {
            // The live files are wiped on the write consumer by core.clearAll(); deleting them
            // from this thread would race a concurrent put() and drop an acknowledged write.
            deleteResidualFallbackFiles(storageDir, baseFileName, exclude = setOf(jsonFile.name, keysFile.name))
        }
    } else {
        val datastoreFile = File(storageDir, "$baseFileName$DATASTORE_FILE_SUFFIX")
        val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
            // A corrupt .preferences_pb otherwise throws on every read forever; set it aside and continue.
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
            // The store file is emptied on the write consumer by core.clearAll(); deleting it from
            // this thread would race a commit. The sweep below matches only `<base>.ksafe`.
            sweepCorruptQuarantineCopies(datastoreFile)
            deleteResidualFallbackFiles(storageDir, baseFileName)
        }

        // Fallback values win over the target, except keys written since a failed attempt.
        if (testEngine == null) {
            val jsonFallback = File(storageDir, "$baseFileName$JSON_FALLBACK_SUFFIX")
            val migrationMarker =
                File(storageDir, "$baseFileName$JSON_FALLBACK_SUFFIX$FALLBACK_MIGRATED_SUFFIX")
            // Compare mtimes, not just marker existence: the `.migrated` archive is permanent, so
            // existence alone would skip a second fallback period forever.
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

/** Deletes fallback residue that still holds recoverable secrets: `.migrated` archives, quarantine
 *  copies, live JSON/key files. Prefix-matched so a sibling safe is never touched. */
private fun deleteResidualFallbackFiles(
    storageDir: File,
    baseFileName: String,
    // The JSON backend's live files are wiped on the write consumer; deleting them from the
    // caller thread would race a concurrent write, so that backend excludes them.
    exclude: Set<String> = emptySet(),
) {
    runCatching {
        val prefix = "$baseFileName.ksafe"
        val liveJson = "$baseFileName$JSON_FALLBACK_SUFFIX"
        val liveKeys = "$baseFileName.ksafe-keys.json"
        storageDir.listFiles()?.forEach { f ->
            val n = f.name
            if (n in exclude) return@forEach
            // Staging temps hold a full plaintext key map; `<base>.` so a sibling isn't touched.
            if (n.endsWith(".fwd-tmp") && n.startsWith("$baseFileName.")) {
                runCatching { f.delete() }
                return@forEach
            }
            if (n.startsWith(prefix) &&
                (n == liveJson || n == liveKeys ||
                    // Crash-leftover FileKeyVault write temps: each a full plaintext key map.
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

/** Builds [KSafeProtectionInfo] from the active vault; a test engine reports its class name. */
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
            // An OS vault exists but failed its self-test, so encrypted ops throw. A separate note
            // from the "no OS vault, software works" case so isEncryptionOperational can tell them apart.
            engine.osVaultUnavailable -> listOf(KSafeProtectionNotes.JVM_OS_VAULT_DEGRADED)
            else     -> listOf(KSafeProtectionNotes.JVM_OS_VAULT_UNAVAILABLE)
        },
    )
}

/** True iff `sun.misc.Unsafe` (JDK module `jdk.unsupported`) is on the runtime. */
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

@PublishedApi
internal val KSafe.dataStore: DataStore<Preferences>
    get() = (core.storage as DataStoreStorage).dataStore

@PublishedApi
internal val KSafe.engine: KSafeEncryption
    get() = core.engine

@PublishedApi
internal fun KSafe.updateCache(prefs: Preferences) {
    val out = toStoredMap(prefs)
    // updateCache is suspend only for web's async decrypt; JVM crypto is blocking.
    kotlinx.coroutines.runBlocking { core.updateCache(out) }
}
