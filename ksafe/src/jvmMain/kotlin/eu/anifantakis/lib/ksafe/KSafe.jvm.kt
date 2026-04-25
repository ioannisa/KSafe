package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.doublePreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.ComparableTimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

@OptIn(ExperimentalEncodingApi::class)
fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

/**
 * JVM implementation of KSafe.
 *
 * This class manages secure key-value storage using:
 * 1. **Jetpack DataStore:** For storing encrypted values (or plain values) on disk.
 * 2. **Software-Backed Encryption:** Unlike Android/iOS, JVM lacks a standard hardware keystore.
 * AES-256 keys are generated and stored alongside the data.
 * 3. **Atomic Hot Cache:** For providing instant, non-blocking reads to the UI.
 * 4. **Hybrid Loading:** Preloads data in background, but falls back to blocking load if accessed early.
 *
 * @property fileName Optional namespace for the storage file. Must be lower-case letters only.
 * @property baseDirFile Optional custom location for the storage file. Directory must exist.
 * @property lazyLoad Whether to start the background preloader immediately.
 * @property memoryPolicy Whether to decrypt and store values in RAM, or keep them encrypted in RAM for additional security
 * @property config Encryption configuration (key size, etc.)
 * @property securityPolicy Security policy for detecting debuggers, etc.
 */
actual class KSafe(
    @PublishedApi internal val fileName: String? = null,
    @PublishedApi internal val baseDirFile: File? = null,
    private val lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    private val config: KSafeConfig = KSafeConfig(),
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    @PublishedApi internal val plaintextCacheTtl: Duration = 5.seconds
) {

    /**
     * Internal constructor for testing with custom encryption engine.
     */
    @PublishedApi
    internal constructor(
        fileName: String? = null,
        baseDirFile: File? = null,
        lazyLoad: Boolean = false,
        memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        config: KSafeConfig = KSafeConfig(),
        securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
        plaintextCacheTtl: Duration = 5.seconds,
        testEngine: KSafeEncryption
    ) : this(fileName, baseDirFile, lazyLoad, memoryPolicy, config, securityPolicy, plaintextCacheTtl) {
        _testEngine = testEngine
    }

    // Internal injection hook for testing
    @PublishedApi
    internal var _testEngine: KSafeEncryption? = null

    companion object {
        // Must start with a lowercase letter; may also contain digits and underscores.
        private val fileNameRegex = Regex("[a-z][a-z0-9_]*")
        private const val GCM_TAG_LENGTH = 128

        /**
         * Sentinel value used to represent null in storage.
         * This allows distinguishing between "key not found" and "key exists with null value".
         */
        @PublishedApi
        internal const val NULL_SENTINEL = "__KSAFE_NULL_VALUE__"

    }

    actual val deviceKeyStorages: Set<KSafeKeyStorage> = setOf(KSafeKeyStorage.SOFTWARE)
    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores")
        }

        // Validate security policy (may throw SecurityViolationException)
        validateSecurityPolicy(securityPolicy)
    }

    /**
     * **Thread-Safe In-Memory Cache (Hot State).**
     *
     * Uses ConcurrentHashMap for O(1) per-key operations instead of copy-on-write.
     */
    @PublishedApi internal val memoryCache = ConcurrentHashMap<String, Any>()

    @PublishedApi
    internal val protectionMap = ConcurrentHashMap<String, String>()

    /**
     * **Short-lived plaintext cache for [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE].**
     */
    @PublishedApi
    internal class CachedPlaintext(val value: String, val expiresAt: ComparableTimeMark)

    @PublishedApi
    internal val plaintextCache = ConcurrentHashMap<String, CachedPlaintext>()

    /**
     * **Cache Initialization Flag.**
     *
     * Tracks whether the cache has been populated from DataStore.
     */
    @PublishedApi internal val cacheInitialized = AtomicBoolean(false)

    @PublishedApi internal val dirtyKeys = ConcurrentHashMap.newKeySet<String>()
    @PublishedApi internal val json: Json = config.json

    @PublishedApi internal val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
        produceFile = {
            val baseDir = if(baseDirFile == null) {
                val homeDir = Paths.get(System.getProperty("user.home")).toFile()
                val homeBaseDir = File(homeDir, ".eu_anifantakis_ksafe")
                if (!homeBaseDir.exists()) {
                    homeBaseDir.mkdirs()
                    secureDirectory(homeBaseDir)
                }
                homeBaseDir
            } else baseDirFile
            val base = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" } ?: "eu_anifantakis_ksafe_datastore"
            val fnameWithSuffix = "$base.preferences_pb"
            File(baseDir, fnameWithSuffix)
        }
    )

    /**
     * Shared CoroutineScope for background write operations.
     * Reusing a single scope avoids the overhead of creating new CoroutineScope + SupervisorJob
     * on every putDirect/deleteDirect call.
     */
    @PublishedApi
    internal val writeScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Sealed class representing a pending write operation for coalescing.
     */
    @PublishedApi
    internal sealed class WriteOperation {
        abstract val rawKey: String

        data class Unencrypted(
            override val rawKey: String,
            val key: String,
            val value: Any?,
            val prefKey: Preferences.Key<Any>
        ) : WriteOperation()

        /**
         * Encrypted write operation.
         * Encryption is deferred to the background batch processor for better UI responsiveness.
         * The plaintext is queued and encrypted just before writing to DataStore.
         */
        data class Encrypted(
            override val rawKey: String,
            val key: String,
            val jsonString: String,
            val alias: String,
            val requireUnlockedDevice: Boolean = false
        ) : WriteOperation()

        data class Delete(
            override val rawKey: String,
            val key: String
        ) : WriteOperation()
    }

    /**
     * Channel for queuing write operations. Uses UNLIMITED capacity to never block putDirect.
     */
    @PublishedApi
    internal val writeChannel = Channel<WriteOperation>(Channel.UNLIMITED)

    /**
     * Configuration for write coalescing.
     */
    private val writeCoalesceWindowMs = 16L  // ~1 frame at 60fps
    private val maxBatchSize = 50

    init {
        // Start the write coalescing consumer
        startWriteConsumer()
    }

    /**
     * Starts the single consumer coroutine that batches and processes write operations.
     */
    private fun startWriteConsumer() {
        writeScope.launch {
            val batch = mutableListOf<WriteOperation>()

            while (true) {
                // Wait for first write
                val firstOp = writeChannel.receive()
                batch.add(firstOp)

                // Collect more writes within the coalesce window
                val deadline = System.currentTimeMillis() + writeCoalesceWindowMs
                while (batch.size < maxBatchSize) {
                    val remaining = deadline - System.currentTimeMillis()
                    if (remaining <= 0) break

                    val nextOp = withTimeoutOrNull(remaining) {
                        writeChannel.receive()
                    }

                    if (nextOp != null) {
                        batch.add(nextOp)
                    } else {
                        break
                    }
                }

                // Process the batch — catch errors to keep the consumer alive.
                // If encryption fails (e.g., device locked with requireUnlockedDevice),
                // we log the error and drop the batch. The consumer must survive so
                // future writes (after device unlock) can still be processed.
                try {
                    processBatch(batch)
                } catch (e: Exception) {
                    println("KSafe: processBatch failed, dropping ${batch.size} writes: ${e.message}")
                }
                batch.clear()
            }
        }
    }

    /**
     * Processes a batch of write operations in a single DataStore edit.
     * Encryption is performed here (in background) rather than in putDirect (on UI thread).
     * Completes all CompletableDeferreds on success, or fails them on error.
     */
    private suspend fun processBatch(batch: List<WriteOperation>) {
        if (batch.isEmpty()) return

        // Collect keys that need encryption key deletion
        val keysToDeleteEncryption = mutableListOf<String>()

        // Pre-encrypt all encrypted operations (done in background, not UI thread)
        val encryptedData = mutableMapOf<String, ByteArray>()
        for (op in batch) {
            if (op is WriteOperation.Encrypted) {
                val ciphertext = engine.encrypt(
                    identifier = op.alias,
                    data = op.jsonString.toByteArray(Charsets.UTF_8),
                    requireUnlockedDevice = op.requireUnlockedDevice
                )
                encryptedData[op.key] = ciphertext
            }
        }

        dataStore.edit { prefs ->
            for (op in batch) {
                when (op) {
                    is WriteOperation.Unencrypted -> {
                        if (op.value == null) {
                            prefs[stringPreferencesKey(valueRawKey(op.key))] = NULL_SENTINEL
                        } else {
                            @Suppress("UNCHECKED_CAST")
                            prefs[op.prefKey] = op.value
                        }
                        prefs[metaPrefKey(op.key)] = protectionToMetaJson(null)
                        // Clean up legacy keys (v1.6/1.7 format)
                        prefs.removeByKeyName(op.key)
                        prefs.remove(legacyEncryptedPrefKey(op.key))
                        prefs.remove(legacyProtectionMetaKey(op.key))
                    }
                    is WriteOperation.Encrypted -> {
                        val ciphertext = encryptedData[op.key]!!
                        prefs[valuePrefKey(op.key)] = encodeBase64(ciphertext)
                        prefs[metaPrefKey(op.key)] = protectionToMetaJson(
                            protection = KSafeProtection.DEFAULT,
                            requireUnlockedDevice = op.requireUnlockedDevice
                        )
                        // Clean up legacy keys (v1.6/1.7 format)
                        prefs.removeByKeyName(op.key)
                        prefs.remove(legacyEncryptedPrefKey(op.key))
                        prefs.remove(legacyProtectionMetaKey(op.key))
                    }
                    is WriteOperation.Delete -> {
                        prefs.removeByKeyName(valueRawKey(op.key))
                        prefs.removeByKeyName(op.key)
                        prefs.remove(legacyEncryptedPrefKey(op.key))
                        prefs.remove(metaPrefKey(op.key))
                        prefs.remove(legacyProtectionMetaKey(op.key))
                        keysToDeleteEncryption.add(op.key)
                    }
                }
            }
        }

        // Delete encryption keys (outside of DataStore edit)
        for (key in keysToDeleteEncryption) {
            val alias = fileName?.let { "$it:$key" } ?: key
            engine.deleteKey(alias)
        }

        // Restore ENCRYPTED semantics: replace plaintext with ciphertext in cache.
        // Uses CAS (replace-if-matches) to avoid overwriting newer putDirect values.
        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED
            || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE
        ) {
            for (op in batch) {
                if (op is WriteOperation.Encrypted) {
                    val ciphertext = encryptedData[op.key]!!
                    val base64Ciphertext = encodeBase64(ciphertext)
                    memoryCache.replace(op.rawKey, op.jsonString, base64Ciphertext)
                }
            }
        }

        // NOTE: Dirty flags are intentionally NOT cleared here.
        // Clearing dirty flags creates race conditions where updateCache runs
        // with stale data after the flag is cleared but before the collector
        // processes our write. Instead, we keep dirty flags set permanently.
        //
        // Trade-off: Small memory overhead from accumulated dirty flags.
        // For typical apps with 100-1000 unique keys, this is negligible (<10KB).
        // Benefit: Guaranteed correctness - optimistic cache values are never
        // overwritten by stale DataStore snapshots.
    }

    // Encryption engine - uses test engine if provided, or creates default JvmSoftwareEncryption
    // Must be initialized after dataStore (lazy to allow _testEngine to be set first)
    @PublishedApi
    internal val engine: KSafeEncryption by lazy {
        _testEngine ?: JvmSoftwareEncryption(config, dataStore)
    }

    private fun secureDirectory(file: File) {
        try {
            val path = file.toPath()
            if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                val permissions = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
                Files.setPosixFilePermissions(path, permissions)
            } else {
                file.setReadable(true, true); file.setWritable(true, true); file.setExecutable(true, true)
            }
        } catch (e: Exception) { System.err.println("KSafe Warning: Could not set secure file permissions: ${e.message}") }
    }

    init {
        // HYBRID CACHE: Start Background Preload immediately.
        // If this finishes before the user calls getDirect, the cache will be ready instantly.
        if (!lazyLoad) {
            startBackgroundCollector()
        }
    }

    private fun startBackgroundCollector() {
        CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
            migrateAccessPolicyIfNeeded()
            cleanupOrphanedCiphertext()
            dataStore.data.collect { updateCache(it) }
        }
    }

    /**
     * Detects and removes orphaned ciphertext entries from DataStore.
     *
     * If the encryption key file is deleted or corrupted, encrypted entries become
     * permanently undecryptable. This method probes each encrypted entry and removes
     * those that can no longer be decrypted.
     */
    private suspend fun cleanupOrphanedCiphertext() {
        val prefs = dataStore.data.first()
        val prefsMap = prefs.asMap()
        val orphanedKeys = mutableListOf<String>()
        val protectionByKey = mutableMapOf<String, KSafeProtection>()

        for ((key, value) in prefsMap) {
            val keyName = key.name
            when {
                keyName.startsWith(KeySafeMetadataManager.META_PREFIX) && keyName.endsWith(KeySafeMetadataManager.META_SUFFIX) -> {
                    val originalKey = keyName.removePrefix(KeySafeMetadataManager.META_PREFIX).removeSuffix(KeySafeMetadataManager.META_SUFFIX)
                    KeySafeMetadataManager.parseProtection(value as? String)?.let { protectionByKey[originalKey] = it }
                }
                KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) != null -> {
                    val originalKey = KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) ?: continue
                    if (!protectionByKey.containsKey(originalKey)) {
                        KeySafeMetadataManager.parseProtection(value as? String)?.let { protectionByKey[originalKey] = it }
                    }
                }
            }
        }

        fun isMissingKeyError(message: String): Boolean {
            return message.contains("No encryption key found", ignoreCase = true) ||
                message.contains("key not found", ignoreCase = true)
        }

        for ((key, value) in prefsMap) {
            val keyName = key.name

            // Preserve legacy encrypted entries to avoid destructive cleanup on upgrades.
            if (keyName.startsWith(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX)) continue
            if (!keyName.startsWith(KeySafeMetadataManager.VALUE_PREFIX)) continue

            val originalKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
            val protection = protectionByKey[originalKey]
            if (protection == null) continue

            val encryptedString = value as? String ?: continue
            val alias = fileName?.let { "$it:$originalKey" } ?: originalKey

            try {
                val ciphertext = decodeBase64(encryptedString)
                engine.decrypt(alias, ciphertext)
            } catch (e: Exception) {
                val msg = e.message ?: ""
                if (isMissingKeyError(msg)) {
                    orphanedKeys.add(keyName)
                }
            }
        }

        if (orphanedKeys.isNotEmpty()) {
            dataStore.edit { mutablePrefs ->
                for (keyName in orphanedKeys) {
                    mutablePrefs.removeByKeyName(keyName)
                    val originalKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                    mutablePrefs.remove(metaPrefKey(originalKey))
                    mutablePrefs.remove(legacyProtectionMetaKey(originalKey))
                }
            }
            for (keyName in orphanedKeys) {
                val originalKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                memoryCache.remove(originalKey)
                memoryCache.remove(legacyEncryptedRawKey(originalKey))
            }
        }
    }

    /** JVM has no lock-based key accessibility concept. */
    private suspend fun migrateAccessPolicyIfNeeded() = Unit

    /**
     * Thread-safe helper to update specific keys in the memory cache.
     * Uses ConcurrentHashMap's O(1) put/remove operations - no copy needed!
     */
    @PublishedApi
    internal fun updateMemoryCache(key: String, value: Any?) {
        if (value == null) {
            memoryCache.remove(key)
        } else {
            memoryCache[key] = value
        }
    }

    @PublishedApi
    internal fun valueRawKey(key: String): String = KeySafeMetadataManager.valueRawKey(key)

    @PublishedApi
    internal fun defaultEncryptedMode(): KSafeWriteMode =
        KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)

    @PublishedApi
    internal fun valuePrefKey(key: String) = stringPreferencesKey(valueRawKey(key))

    @PublishedApi
    internal fun metaPrefKey(key: String) = stringPreferencesKey(KeySafeMetadataManager.metadataRawKey(key))

    @PublishedApi
    internal fun legacyEncryptedPrefKey(key: String) =
        stringPreferencesKey(KeySafeMetadataManager.legacyEncryptedRawKey(key))

    @PublishedApi
    internal fun legacyProtectionMetaKey(key: String) =
        stringPreferencesKey(KeySafeMetadataManager.legacyProtectionRawKey(key))

    @PublishedApi
    internal fun legacyEncryptedRawKey(key: String): String =
        KeySafeMetadataManager.legacyEncryptedRawKey(key)

    @PublishedApi
    internal fun protectionToMetaJson(
        protection: KSafeProtection?,
        requireUnlockedDevice: Boolean? = null
    ): String {
        val accessPolicy = if (protection == null) null
        else KeySafeMetadataManager.accessPolicyFor(requireUnlockedDevice == true)
        return KeySafeMetadataManager.buildMetadataJson(protection, accessPolicy)
    }

    @PublishedApi
    @Suppress("UNCHECKED_CAST")
    internal fun MutablePreferences.removeByKeyName(name: String) {
        asMap().keys.firstOrNull { it.name == name }?.let { remove(it as Preferences.Key<Any?>) }
    }

    @PublishedApi
    internal fun MutablePreferences.removeAllLegacyKeys(key: String) {
        removeByKeyName(key)
        remove(legacyEncryptedPrefKey(key))
        remove(legacyProtectionMetaKey(key))
    }

    /**
     * Checks if the given value represents a stored null (using the sentinel).
     */
    @PublishedApi
    internal fun isNullSentinel(value: Any?): Boolean {
        return value == NULL_SENTINEL
    }

    /**
     * Updates the [memoryCache] based on the raw [Preferences] from DataStore.
     *
     * **Lock-Free Design:**
     * Uses ConcurrentHashMap for O(1) per-key updates instead of atomic map replacement.
     * The dirty keys mechanism ensures that optimistic writes from [putDirect] are not
     * overwritten by stale data from DataStore during the write window.
     */
    @PublishedApi
    internal fun updateCache(prefs: Preferences) {
        val prefsMap = prefs.asMap()
        val currentDirty: Set<String> = try { HashSet(dirtyKeys) } catch (_: Exception) { emptySet() }
        val existingMetadata = HashMap(protectionMap)
        val validCacheKeys = mutableSetOf<String>()

        fun isDirtyForUserKey(userKey: String): Boolean {
            val canonical = valueRawKey(userKey)
            val legacyEncrypted = legacyEncryptedRawKey(userKey)
            return currentDirty.contains(canonical)
                || currentDirty.contains(userKey)
                || currentDirty.contains(legacyEncrypted)
        }

        val metadataEntries = prefsMap.map { (prefKey, prefValue) -> prefKey.name to (prefValue as? String) }
        val protectionByKey = KeySafeMetadataManager.collectMetadata(
            entries = metadataEntries,
            accept = { userKey -> !isDirtyForUserKey(userKey) }
        ).toMutableMap()

        // Pass 2: collect data into cache (canonical + legacy fallback)
        for ((prefKey, prefValue) in prefsMap) {
            val keyName = prefKey.name
            val classified = KeySafeMetadataManager.classifyStorageEntry(
                rawKey = keyName,
                legacyEncryptedPrefix = KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX,
                encryptedCacheKeyForUser = { userKey -> legacyEncryptedRawKey(userKey) },
                stagedMetadata = protectionByKey,
                existingMetadata = existingMetadata
            ) ?: continue

            val userKey = classified.userKey
            val cacheKey = classified.cacheKey
            val explicitEncrypted = classified.encrypted

            if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKey(userKey)) {
                protectionByKey[userKey] = if (explicitEncrypted) "DEFAULT" else "NONE"
            }

            if (isDirtyForUserKey(userKey) || currentDirty.contains(cacheKey)) {
                validCacheKeys.add(cacheKey)
                continue
            }

            validCacheKeys.add(cacheKey)

            if (explicitEncrypted == true) {
                val encryptedString = prefValue as? String ?: continue
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED
                    || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE
                ) {
                    memoryCache[cacheKey] = encryptedString
                } else {
                    try {
                        val alias = fileName?.let { "$it:$userKey" } ?: userKey
                        val encryptedBytes = decodeBase64(encryptedString)
                        val plainBytes = engine.decrypt(alias, encryptedBytes)
                        memoryCache[cacheKey] = plainBytes.toString(Charsets.UTF_8)
                    } catch (_: Exception) { }
                }
            } else {
                memoryCache[cacheKey] = prefValue
            }
        }

        validCacheKeys.addAll(currentDirty)

        try {
            val keysToRemove = memoryCache.keys.filter { it !in validCacheKeys && !dirtyKeys.contains(it) }
            keysToRemove.forEach { memoryCache.remove(it) }
        } catch (_: Exception) { }

        // Sync metadata cache (while preserving dirty optimistic keys)
        val existingKeys = protectionMap.keys.toList()
        for ((userKey, rawMeta) in protectionByKey) {
            if (!isDirtyForUserKey(userKey)) {
                protectionMap[userKey] = KeySafeMetadataManager.extractProtectionLiteral(rawMeta)
            }
        }
        for (userKey in existingKeys) {
            if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKey(userKey)) {
                protectionMap.remove(userKey)
            }
        }

        cacheInitialized.set(true)
    }

    @PublishedApi internal inline fun <reified T> resolveFromCache(cache: Map<String, Any>, key: String, defaultValue: T, protection: KSafeProtection?): T {
        val cacheKey = if (protection != null) legacyEncryptedRawKey(key) else key
        val cachedValue = cache[cacheKey] ?: return defaultValue

        return if (protection != null) {
            var jsonString: String? = null
            var deserializedValue: T? = null
            var success = false

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                // TIMED_CACHE: check plaintext cache first (avoids decryption on repeated reads)
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                    val cached = plaintextCache[cacheKey]
                    if (cached != null && TimeSource.Monotonic.markNow() < cached.expiresAt) {
                        val cachedJson = cached.value
                        if (cachedJson == NULL_SENTINEL) {
                            @Suppress("UNCHECKED_CAST")
                            return null as T
                        }
                        try {
                            return json.decodeFromString(serializer<T>(), cachedJson)
                        } catch (_: Exception) { /* fall through to decrypt */ }
                    }
                }

                // SECURITY MODE: Decrypt On-Demand
                try {
                    val encryptedString = cachedValue as? String
                    if (encryptedString != null) {
                        val ciphertext = decodeBase64(encryptedString)

                        // Decrypt using the engine
                        val alias = fileName?.let { "$it:$key" } ?: key
                        val plainBytes = engine.decrypt(alias, ciphertext)

                        val candidateJson = plainBytes.toString(Charsets.UTF_8)

                        // Try deserializing to verify it's valid JSON
                        if (candidateJson == NULL_SENTINEL) {
                            @Suppress("UNCHECKED_CAST")
                            deserializedValue = null as T
                        } else {
                            deserializedValue = json.decodeFromString(serializer<T>(), candidateJson)
                        }
                        success = true

                        // Populate the timed plaintext cache on successful decrypt
                        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                            plaintextCache[cacheKey] = CachedPlaintext(candidateJson, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
                        }
                    }
                } catch (_: Exception) {
                    // Decryption failed OR deserialization of decrypted data failed.
                    // Fall through to try plaintext fallback.
                }
            } else {
                // PERFORMANCE MODE: Already decrypted
                jsonString = cachedValue as? String
            }

            if (success) {
                return deserializedValue as T
            }

            // FALLBACK / PERFORMANCE MODE Handling
            // If we haven't successfully decrypted+deserialized yet, assume cachedValue is Plain JSON (Optimistic Update)
            if (jsonString == null) {
                jsonString = cachedValue as? String
            }

            if (jsonString == null) return defaultValue

            // Check for null sentinel
            if (jsonString == NULL_SENTINEL) {
                @Suppress("UNCHECKED_CAST")
                return null as T
            }

            try { json.decodeFromString(serializer<T>(), jsonString) } catch (_: Exception) { defaultValue }
        } else {
            // Check for null sentinel first
            if (isNullSentinel(cachedValue)) {
                @Suppress("UNCHECKED_CAST")
                return null as T
            }
            convertStoredValue(cachedValue, defaultValue)
        }
    }

    /**
     * Non-inline version of [resolveFromCache]. All cache lookup, decryption,
     * Base64 decode and timed-cache logic lives here. Returns raw [Any?].
     */
    internal fun resolveFromCacheRaw(cache: Map<String, Any>, key: String, defaultValue: Any?, protection: KSafeProtection?, serializer: KSerializer<*>): Any? {
        val cacheKey = if (protection != null) legacyEncryptedRawKey(key) else key
        val cachedValue = cache[cacheKey] ?: return defaultValue

        return if (protection != null) {
            var jsonString: String? = null
            var deserializedValue: Any? = null
            var success = false

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                    val cached = plaintextCache[cacheKey]
                    if (cached != null && TimeSource.Monotonic.markNow() < cached.expiresAt) {
                        val cachedJson = cached.value
                        if (cachedJson == NULL_SENTINEL) return null
                        try { return jsonDecode(json, serializer, cachedJson) } catch (_: Exception) { /* fall through */ }
                    }
                }

                try {
                    val encryptedString = cachedValue as? String
                    if (encryptedString != null) {
                        val ciphertext = decodeBase64(encryptedString)
                        val alias = fileName?.let { "$it:$key" } ?: key
                        val plainBytes = engine.decrypt(alias, ciphertext)
                        val candidateJson = plainBytes.toString(Charsets.UTF_8)

                        deserializedValue = if (candidateJson == NULL_SENTINEL) null
                            else jsonDecode(json, serializer, candidateJson)
                        success = true

                        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                            plaintextCache[cacheKey] = CachedPlaintext(candidateJson, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
                        }
                    }
                } catch (_: Exception) { }
            } else {
                jsonString = cachedValue as? String
            }

            if (success) return deserializedValue
            if (jsonString == null) jsonString = cachedValue as? String
            if (jsonString == null) return defaultValue
            if (jsonString == NULL_SENTINEL) return null
            try { jsonDecode(json, serializer, jsonString) } catch (_: Exception) { defaultValue }
        } else {
            if (isNullSentinel(cachedValue)) return null
            convertStoredValueRaw(cachedValue, defaultValue, serializer)
        }
    }

    @PublishedApi internal inline fun <reified T> convertStoredValue(storedValue: Any?, defaultValue: T): T {
        if (storedValue == null) return defaultValue

        // Check for null sentinel
        if (isNullSentinel(storedValue)) {
            @Suppress("UNCHECKED_CAST")
            return null as T
        }

        return when (defaultValue) {
            is Boolean -> (storedValue as? Boolean ?: defaultValue) as T
            is Int -> {
                when (storedValue) {
                    is Int -> storedValue as T
                    is Long -> if (storedValue in Int.MIN_VALUE..Int.MAX_VALUE) storedValue.toInt() as T else defaultValue
                    else -> defaultValue
                }
            }
            is Long -> {
                when (storedValue) {
                    is Long -> storedValue as T
                    is Int -> storedValue.toLong() as T
                    else -> defaultValue
                }
            }
            is Float -> (storedValue as? Float ?: defaultValue) as T
            is String -> (storedValue as? String ?: defaultValue) as T
            is Double -> (storedValue as? Double ?: defaultValue) as T
            else -> {
                // For nullable types where defaultValue is null, we need special handling.
                // Try direct cast first — storedValue may be a primitive (String, Boolean, etc.)
                // that matches T without JSON deserialization.
                try {
                    @Suppress("UNCHECKED_CAST")
                    val direct = storedValue as T
                    if (direct != null) return direct
                } catch (_: ClassCastException) { /* fall through to JSON */ }

                val jsonString = storedValue as? String ?: return defaultValue
                if (jsonString == NULL_SENTINEL) {
                    @Suppress("UNCHECKED_CAST")
                    return null as T
                }
                try {
                    json.decodeFromString(serializer<T>(), jsonString)
                } catch (_: Exception) {
                    defaultValue
                }
            }
        }
    }

    /**
     * Non-inline version of [convertStoredValue]. Handles primitive type branches
     * without reified T; uses [serializer] for the JSON `else` branch.
     */
    @Suppress("UNCHECKED_CAST")
    internal fun convertStoredValueRaw(storedValue: Any?, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (storedValue == null) return defaultValue
        if (isNullSentinel(storedValue)) return null

        return when (defaultValue) {
            is Boolean -> (storedValue as? Boolean ?: defaultValue)
            is Int -> when (storedValue) {
                is Int -> storedValue
                is Long -> if (storedValue in Int.MIN_VALUE..Int.MAX_VALUE) storedValue.toInt() else defaultValue
                else -> defaultValue
            }
            is Long -> when (storedValue) {
                is Long -> storedValue
                is Int -> storedValue.toLong()
                else -> defaultValue
            }
            is Float -> (storedValue as? Float ?: defaultValue)
            is String -> (storedValue as? String ?: defaultValue)
            is Double -> (storedValue as? Double ?: defaultValue)
            else -> {
                // Non-String stored values (e.g., Int from DataStore for Int? type)
                if (storedValue !is String) return storedValue
                if (storedValue == NULL_SENTINEL) return null
                // For String/String? types, return raw value (stored unencoded)
                if (isStringSerializer(serializer)) return storedValue
                // For @Serializable types, JSON deserialize
                try { jsonDecode(json, serializer, storedValue) } catch (_: Exception) { defaultValue }
            }
        }
    }

    // --- PUBLIC API ---

    actual inline fun <reified T> getDirect(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return getDirectRaw(key, defaultValue, serializer<T>()) as T
    }

    @PublishedApi
    internal actual fun getDirectRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (!cacheInitialized.get()) {
            runBlocking {
                if (!cacheInitialized.get()) {
                    val prefs = dataStore.data.first()
                    updateCache(prefs)
                }
            }
        }
        val detected = detectProtection(key)
        return resolveFromCacheRaw(memoryCache, key, defaultValue, detected, serializer)
    }


    actual inline fun <reified T> putDirect(key: String, value: T) {
        putDirectRaw(key, value, defaultEncryptedMode(), serializer<T>())
    }

    actual inline fun <reified T> putDirect(key: String, value: T, mode: KSafeWriteMode) {
        putDirectRaw(key, value, mode, serializer<T>())
    }

    @PublishedApi
    internal actual fun putDirectRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) {
        val protection = mode.toProtection()
        val requireUnlockedDevice = mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice
        val rawKey = if (protection != null) "encrypted_$key" else key
        dirtyKeys.add(rawKey)

        if (protection != null) {
            val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
            val alias = fileName?.let { "$it:$key" } ?: key

            updateMemoryCache(rawKey, jsonString)
            protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(KSafeProtection.DEFAULT)

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                plaintextCache[rawKey] = CachedPlaintext(jsonString, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
            }

            writeChannel.trySend(
                WriteOperation.Encrypted(
                    rawKey = rawKey,
                    key = key,
                    jsonString = jsonString,
                    alias = alias,
                    requireUnlockedDevice = requireUnlockedDevice
                )
            )
        } else {
            val toCache: Any = if (value == null) {
                NULL_SENTINEL
            } else {
                when (value) {
                    is Boolean, is Int, is Long, is Float, is Double, is String -> value
                    else -> jsonEncode(json, serializer, value)
                }
            }
            updateMemoryCache(rawKey, toCache)
            protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(null)

            val storedValue: Any? = when (value) {
                null -> null
                is Boolean, is Int, is Long, is Float, is Double, is String -> value
                else -> jsonEncode(json, serializer, value)
            }

            @Suppress("UNCHECKED_CAST")
            val prefKey = when (value) {
                is Boolean -> booleanPreferencesKey(valueRawKey(key))
                is Int -> intPreferencesKey(valueRawKey(key))
                is Long -> longPreferencesKey(valueRawKey(key))
                is Float -> floatPreferencesKey(valueRawKey(key))
                is Double -> doublePreferencesKey(valueRawKey(key))
                is String -> stringPreferencesKey(valueRawKey(key))
                else -> stringPreferencesKey(valueRawKey(key))
            } as Preferences.Key<Any>

            writeChannel.trySend(WriteOperation.Unencrypted(rawKey, key, storedValue, prefKey))
        }
    }

    @PublishedApi
    internal fun encryptedPrefKey(key: String) = legacyEncryptedPrefKey(key)

    @PublishedApi
    internal fun protectionMetaKey(key: String) = legacyProtectionMetaKey(key)

    @PublishedApi
    internal fun detectProtection(key: String): KSafeProtection? {
        val meta = protectionMap[key]
        KeySafeMetadataManager.parseProtection(meta)?.let { return it }
        // Fallback heuristic (legacy data without metadata)
        return if (memoryCache.containsKey(KeySafeMetadataManager.legacyEncryptedRawKey(key))) KSafeProtection.DEFAULT
        else null
    }

    // --- Non-inline suspend helpers ---

    @PublishedApi
    internal suspend fun putEncryptedRaw(
        key: String,
        value: Any?,
        requireUnlockedDevice: Boolean,
        serializer: KSerializer<*>
    ) {
        dirtyKeys.add(legacyEncryptedRawKey(key))
        protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(KSafeProtection.DEFAULT)
        val alias = fileName?.let { "$it:$key" } ?: key

        val rawString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)

        val plainBytes = rawString.toByteArray(Charsets.UTF_8)
        val encryptedBytes = withContext(Dispatchers.Default) {
            engine.encrypt(
                identifier = alias,
                data = plainBytes,
                requireUnlockedDevice = requireUnlockedDevice
            )
        }
        val encryptedString = encodeBase64(encryptedBytes)

        dataStore.edit { prefs ->
            prefs[valuePrefKey(key)] = encryptedString
            prefs[metaPrefKey(key)] = protectionToMetaJson(
                protection = KSafeProtection.DEFAULT,
                requireUnlockedDevice = requireUnlockedDevice
            )
            prefs.removeAllLegacyKeys(key)
        }

        val cacheValue = if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
            encryptedString
        } else {
            rawString
        }
        updateMemoryCache(legacyEncryptedRawKey(key), cacheValue)

        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
            plaintextCache[legacyEncryptedRawKey(key)] = CachedPlaintext(rawString, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
        }
    }

    suspend inline fun <reified T> putEncrypted(
        key: String,
        value: T,
        requireUnlockedDevice: Boolean = false
    ) {
        putEncryptedRaw(key, value, requireUnlockedDevice, serializer<T>())
    }

    @PublishedApi
    internal suspend fun getEncryptedRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (cacheInitialized.get()) {
            return withContext(Dispatchers.Default) {
                resolveFromCacheRaw(memoryCache, key, defaultValue, protection = KSafeProtection.DEFAULT, serializer)
            }
        }
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return withContext(Dispatchers.Default) {
            resolveFromCacheRaw(memoryCache, key, defaultValue, protection = KSafeProtection.DEFAULT, serializer)
        }
    }

    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return getEncryptedRaw(key, defaultValue, serializer<T>()) as T
    }

    actual suspend inline fun <reified T> get(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return getRaw(key, defaultValue, serializer<T>()) as T
    }

    @PublishedApi
    internal actual suspend fun getRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (!cacheInitialized.get()) {
            val prefs = dataStore.data.first()
            updateCache(prefs)
        }
        val detected = detectProtection(key)
        return if (detected != null) getEncryptedRaw(key, defaultValue, serializer) else getUnencryptedRaw(key, defaultValue, serializer)
    }


    @PublishedApi
    internal suspend fun getUnencryptedRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (cacheInitialized.get()) {
            return resolveFromCacheRaw(memoryCache, key, defaultValue, protection = null, serializer)
        }
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return resolveFromCacheRaw(memoryCache, key, defaultValue, protection = null, serializer)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        return getUnencryptedRaw(key, defaultValue, serializer<T>()) as T
    }

    @PublishedApi
    internal suspend fun putUnencryptedRaw(key: String, value: Any?, serializer: KSerializer<*>) {
        dirtyKeys.add(key)
        protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(null)
        if (value == null) {
            val preferencesKey = stringPreferencesKey(valueRawKey(key))
            dataStore.edit { prefs ->
                prefs[preferencesKey] = NULL_SENTINEL
                prefs[metaPrefKey(key)] = protectionToMetaJson(null)
                prefs.removeAllLegacyKeys(key)
            }
            updateMemoryCache(key, NULL_SENTINEL)
            return
        }

        val preferencesKey = getUnencryptedKey(key, defaultValue = value)
        val storedValue: Any = when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> value
            else -> jsonEncode(json, serializer, value)
        }
        dataStore.edit { prefs ->
            prefs[preferencesKey] = storedValue
            prefs[metaPrefKey(key)] = protectionToMetaJson(null)
            prefs.removeAllLegacyKeys(key)
        }
        updateMemoryCache(key, storedValue)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal suspend inline fun <reified T> putUnencrypted(key: String, value: T) {
        putUnencryptedRaw(key, value, serializer<T>())
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal fun <T> getUnencryptedKey(key: String, defaultValue: T): Preferences.Key<Any> {
        return when (defaultValue) {
            is Boolean -> booleanPreferencesKey(valueRawKey(key))
            is Int -> intPreferencesKey(valueRawKey(key))
            is Long -> longPreferencesKey(valueRawKey(key))
            is Float -> floatPreferencesKey(valueRawKey(key))
            is String -> stringPreferencesKey(valueRawKey(key))
            is Double -> doublePreferencesKey(valueRawKey(key))
            else -> stringPreferencesKey(valueRawKey(key))
        } as Preferences.Key<Any>
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi
    internal fun <T> getLegacyUnencryptedKey(key: String, defaultValue: T): Preferences.Key<Any> {
        return when (defaultValue) {
            is Boolean -> booleanPreferencesKey(key)
            is Int -> intPreferencesKey(key)
            is Long -> longPreferencesKey(key)
            is Float -> floatPreferencesKey(key)
            is String -> stringPreferencesKey(key)
            is Double -> doublePreferencesKey(key)
            else -> stringPreferencesKey(key)
        } as Preferences.Key<Any>
    }

    actual inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> {
        @Suppress("UNCHECKED_CAST")
        return getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
    }

    @PublishedApi
    internal actual fun getFlowRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Flow<Any?> {
        return dataStore.data.map { preferences ->
            val metaRaw = preferences[metaPrefKey(key)] ?: preferences[legacyProtectionMetaKey(key)]
            val protection = KeySafeMetadataManager.parseProtection(metaRaw)
                ?: if (preferences[encryptedPrefKey(key)] != null) KSafeProtection.DEFAULT else null
            when (protection) {
                null -> {
                    val prefKey = getUnencryptedKey(key, defaultValue)
                    val legacyPrefKey = getLegacyUnencryptedKey(key, defaultValue)
                    val plain = preferences[prefKey] ?: preferences[legacyPrefKey]
                    if (plain != null) convertStoredValueRaw(plain, defaultValue, serializer)
                    else defaultValue
                }
                else -> {
                    val enc = preferences[valuePrefKey(key)] ?: preferences[encryptedPrefKey(key)]
                    if (enc != null) {
                        try {
                            val alias = fileName?.let { "$it:$key" } ?: key
                            val ciphertext = decodeBase64(enc)
                            val plainBytes = engine.decrypt(alias, ciphertext)
                            val rawString = plainBytes.toString(Charsets.UTF_8)
                            if (rawString == NULL_SENTINEL) null
                            else jsonDecode(json, serializer, rawString)
                        } catch (_: Exception) { defaultValue }
                    } else defaultValue
                }
            }
        }.distinctUntilChanged()
    }


    @PublishedApi internal inline fun <reified T> getUnencryptedFlow(key: String, defaultValue: T): Flow<T> {
        @Suppress("UNCHECKED_CAST")
        return getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
    }

    @PublishedApi internal inline fun <reified T> getEncryptedFlow(key: String, defaultValue: T): Flow<T> {
        @Suppress("UNCHECKED_CAST")
        return getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
    }

    actual suspend inline fun <reified T> put(key: String, value: T) {
        putRaw(key, value, defaultEncryptedMode(), serializer<T>())
    }

    actual suspend inline fun <reified T> put(key: String, value: T, mode: KSafeWriteMode) {
        putRaw(key, value, mode, serializer<T>())
    }

    @PublishedApi
    internal actual suspend fun putRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) {
        if (mode is KSafeWriteMode.Encrypted) {
            putEncryptedRaw(key, value, mode.requireUnlockedDevice, serializer)
        } else {
            putUnencryptedRaw(key, value, serializer)
        }
    }

    actual suspend fun delete(key: String) {
        dataStore.edit {
            it.removeByKeyName(valueRawKey(key))
            it.remove(metaPrefKey(key))
            it.removeAllLegacyKeys(key)
        }
        // Delete the encryption key using the engine
        val alias = fileName?.let { "$it:$key" } ?: key
        engine.deleteKey(alias)

        updateMemoryCache(key, null)
        updateMemoryCache(legacyEncryptedRawKey(key), null)
        plaintextCache.remove(key)
        plaintextCache.remove(legacyEncryptedRawKey(key))
        protectionMap.remove(key)
    }

    actual fun deleteDirect(key: String) {
        val rawKey = key
        val encKeyName = legacyEncryptedRawKey(key)

        // Mark keys as dirty
        dirtyKeys.add(rawKey)
        dirtyKeys.add(encKeyName)

        // Optimistic cache update
        updateMemoryCache(key, null)
        updateMemoryCache(encKeyName, null)
        plaintextCache.remove(rawKey)
        plaintextCache.remove(encKeyName)
        protectionMap.remove(key)

        // Queue delete operation for batched processing
        writeChannel.trySend(WriteOperation.Delete(rawKey, key))
    }

    actual suspend fun clearAll() {
        dataStore.edit { it.clear() }
        try {
            val homeDir = Paths.get(System.getProperty("user.home")).toFile()
            val baseDir = File(homeDir, ".eu_anifantakis_ksafe")
            val base = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" } ?: "eu_anifantakis_ksafe_datastore"
            val fnameWithSuffix = "$base.preferences_pb"
            val file = File(baseDir, fnameWithSuffix)
            if (file.exists()) file.delete()
        } catch (_: Exception) { }
        memoryCache.clear()
        plaintextCache.clear()
        protectionMap.clear()
    }

    // --- PER-KEY STORAGE QUERY ---

    actual fun getKeyInfo(key: String): KSafeKeyInfo? {
        if (!cacheInitialized.get()) {
            runBlocking {
                if (!cacheInitialized.get()) {
                    val prefs = dataStore.data.first()
                    updateCache(prefs)
                }
            }
        }

        val hasEncrypted = memoryCache.containsKey(legacyEncryptedRawKey(key))
        val hasPlain = memoryCache.containsKey(key)
        if (!hasEncrypted && !hasPlain) return null

        val protection = KeySafeMetadataManager.parseProtection(protectionMap[key])
            ?: if (hasEncrypted) KSafeProtection.DEFAULT else null
        return KSafeKeyInfo(protection, KSafeKeyStorage.SOFTWARE)
    }


    // --- DEPRECATED OVERLOADS (encrypted: Boolean) ---

    @Suppress("DEPRECATION")
    @Deprecated("Remove \"encrypted\" parameter. Protection is now auto-detected during reads.  Your \"encrypted\" param is ignored.", level = DeprecationLevel.WARNING)
    actual inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean): T =
        getDirect(key, defaultValue)

    @Suppress("DEPRECATION")
    @Deprecated("Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain", level = DeprecationLevel.WARNING)
    actual inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean): Unit =
        putDirect(
            key,
            value,
            if (encrypted) {
                defaultEncryptedMode()
            } else {
                KSafeWriteMode.Plain
            }
        )

    @Suppress("DEPRECATION")
    @Deprecated("Remove \"encrypted\" parameter. Protection is now auto-detected during reads.  Your \"encrypted\" param is ignored.", level = DeprecationLevel.WARNING)
    actual suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean): T =
        get(key, defaultValue)

    @Suppress("DEPRECATION")
    @Deprecated("Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain", level = DeprecationLevel.WARNING)
    actual suspend inline fun <reified T> put(key: String, value: T, encrypted: Boolean): Unit =
        put(
            key,
            value,
            if (encrypted) {
                defaultEncryptedMode()
            } else {
                KSafeWriteMode.Plain
            }
        )

    @Suppress("DEPRECATION")
    @Deprecated("Remove \"encrypted\" parameter. Protection is now auto-detected during reads.  Your \"encrypted\" param is ignored.", level = DeprecationLevel.WARNING)
    actual inline fun <reified T> getFlow(key: String, defaultValue: T, encrypted: Boolean): Flow<T> =
        getFlow(key, defaultValue)

    /**
     * Verifies biometric authentication.
     * On JVM, always returns true (no biometric hardware).
     *
     * @param reason The reason string (ignored on JVM)
     * @param authorizationDuration Duration configuration (ignored on JVM)
     */
    actual suspend fun verifyBiometric(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?
    ): Boolean {
        // No biometric hardware on JVM
        return true
    }

    /**
     * Verifies biometric authentication (non-blocking).
     * On JVM, always returns true (no biometric hardware).
     *
     * @param reason The reason string (ignored on JVM)
     * @param authorizationDuration Duration configuration (ignored on JVM)
     * @param onResult Callback with true (always succeeds on JVM)
     */
    actual fun verifyBiometricDirect(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
        onResult: (Boolean) -> Unit
    ) {
        // No biometric hardware on JVM
        onResult(true)
    }

    /**
     * Clears cached biometric authorization.
     * On JVM, this is a no-op (no biometric hardware).
     *
     * @param scope The scope to clear (ignored on JVM)
     */
    actual fun clearBiometricAuth(scope: String?) {
        // No biometric hardware on JVM - nothing to clear
    }
}
