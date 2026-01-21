package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
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
import kotlinx.coroutines.withTimeoutOrNull
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
import java.util.concurrent.atomic.AtomicReference

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
 * @property lazyLoad Whether to start the background preloader immediately.
 * @property memoryPolicy Whether to decrypt and store values in RAM, or keep them encrypted in RAM for additional security
 * @property config Encryption configuration (key size, etc.)
 * @property securityPolicy Security policy for detecting debuggers, etc.
 */
actual class KSafe(
    @PublishedApi internal val fileName: String? = null,
    private val lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    private val config: KSafeConfig = KSafeConfig(),
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default
) {

    /**
     * Internal constructor for testing with custom encryption engine.
     */
    @PublishedApi
    internal constructor(
        fileName: String? = null,
        lazyLoad: Boolean = false,
        memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        config: KSafeConfig = KSafeConfig(),
        securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
        testEngine: KSafeEncryption
    ) : this(fileName, lazyLoad, memoryPolicy, config, securityPolicy) {
        _testEngine = testEngine
    }

    // Internal injection hook for testing
    @PublishedApi
    internal var _testEngine: KSafeEncryption? = null

    companion object {
        private val fileNameRegex = Regex("[a-z]+")
        private const val GCM_TAG_LENGTH = 128

        /**
         * Sentinel value used to represent null in storage.
         * This allows distinguishing between "key not found" and "key exists with null value".
         */
        @PublishedApi
        internal const val NULL_SENTINEL = "__KSAFE_NULL_VALUE__"
    }

    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must contain only lowercase letters")
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

    /**
     * **Cache Initialization Flag.**
     *
     * Tracks whether the cache has been populated from DataStore.
     */
    @PublishedApi internal val cacheInitialized = AtomicBoolean(false)

    @PublishedApi internal val dirtyKeys = ConcurrentHashMap.newKeySet<String>()
    @PublishedApi internal val json = Json { ignoreUnknownKeys = true }

    @PublishedApi internal val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
        produceFile = {
            val homeDir = Paths.get(System.getProperty("user.home")).toFile()
            val baseDir = File(homeDir, ".eu_anifantakis_ksafe")
            if (!baseDir.exists()) {
                baseDir.mkdirs()
                secureDirectory(baseDir)
            }
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
            val alias: String
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

                // Process the batch
                processBatch(batch)
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
                val ciphertext = engine.encrypt(op.alias, op.jsonString.toByteArray(Charsets.UTF_8))
                encryptedData[op.key] = ciphertext
            }
        }

        dataStore.edit { prefs ->
            for (op in batch) {
                when (op) {
                    is WriteOperation.Unencrypted -> {
                        if (op.value == null) {
                            prefs[stringPreferencesKey(op.key)] = NULL_SENTINEL
                        } else {
                            @Suppress("UNCHECKED_CAST")
                            prefs[op.prefKey] = op.value
                        }
                    }
                    is WriteOperation.Encrypted -> {
                        val ciphertext = encryptedData[op.key]!!
                        prefs[encryptedPrefKey(op.key)] = encodeBase64(ciphertext)
                    }
                    is WriteOperation.Delete -> {
                        prefs.remove(stringPreferencesKey(op.key))
                        prefs.remove(encryptedPrefKey(op.key))
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
            dataStore.data.collect { updateCache(it) }
        }
    }

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
        val encryptedPrefix = "encrypted_"
        // Snapshot of dirty keys - use try-catch to handle concurrent modification
        val currentDirty: Set<String> = try {
            HashSet(dirtyKeys)
        } catch (e: NoSuchElementException) {
            emptySet()
        }

        // Build set of keys that should exist based on DataStore
        val validKeys = mutableSetOf<String>()

        for ((key, value) in prefsMap) {
            val keyName = key.name

            // Dirty Check: If a local write was pending at snapshot time,
            // skip updating from disk (preserve optimistic value).
            // Use the SNAPSHOT for this check to avoid race conditions.
            // NOTE: We do NOT clear dirty flags here because the DataStore snapshot
            // might contain OLD data, not the data from our pending write.
            // Dirty flags are cleared in processBatch after successful persistence.
            if (currentDirty.contains(keyName)) {
                validKeys.add(keyName)
                continue
            }

            if (keyName.startsWith(encryptedPrefix)) {
                validKeys.add(keyName)
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
                    // POLICY: ENCRYPTED -> Store raw ciphertext
                    memoryCache[keyName] = value
                } else {
                    // POLICY: PLAIN_TEXT -> Decrypt immediately
                    val originalKey = keyName.removePrefix(encryptedPrefix)
                    val encryptedString = value as? String
                    if (encryptedString != null) {
                        try {
                            val alias = fileName?.let { "$it:$originalKey" } ?: originalKey
                            val encryptedBytes = decodeBase64(encryptedString)
                            val plainBytes = engine.decrypt(alias, encryptedBytes)
                            memoryCache[keyName] = plainBytes.toString(Charsets.UTF_8)
                        } catch (_: Exception) { /* Ignore failures */ }
                    }
                }
            } else if (!keyName.startsWith("ksafe_")) {
                validKeys.add(keyName)
                memoryCache[keyName] = value
            }
        }

        // Also preserve all dirty keys as valid (they're being written)
        validKeys.addAll(currentDirty)

        // Remove keys that no longer exist in DataStore (except dirty ones)
        try {
            val keysToRemove = memoryCache.keys.filter { it !in validKeys }
            keysToRemove.forEach { memoryCache.remove(it) }
        } catch (e: NoSuchElementException) {
            // Concurrent modification - skip cleanup this cycle
        }

        // Mark cache as initialized
        cacheInitialized.set(true)
    }

    @PublishedApi internal inline fun <reified T> resolveFromCache(cache: Map<String, Any>, key: String, defaultValue: T, encrypted: Boolean): T {
        val cacheKey = if (encrypted) "encrypted_$key" else key
        val cachedValue = cache[cacheKey] ?: return defaultValue

        return if (encrypted) {
            var jsonString: String? = null
            var deserializedValue: T? = null
            var success = false

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
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
                // For nullable types where defaultValue is null, we need special handling
                if (defaultValue == null) {
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
                } else {
                    val jsonString = storedValue as? String ?: return defaultValue
                    try {
                        json.decodeFromString(serializer<T>(), jsonString)
                    } catch (_: Exception) {
                        defaultValue
                    }
                }
            }
        }
    }

    // --- PUBLIC API ---

    actual inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean): T {
        // 1. FAST PATH (Hot Cache)
        if (cacheInitialized.get()) {
            return resolveFromCache(memoryCache, key, defaultValue, encrypted)
        }

        // 2. FALLBACK PATH (Cold Cache)
        // Matches Hybrid logic: Block main thread once to load cache if accessed too early.
        return runBlocking {
            // Double-check optimization
            if (cacheInitialized.get()) {
                return@runBlocking resolveFromCache(memoryCache, key, defaultValue, encrypted)
            }

            val prefs = dataStore.data.first()
            updateCache(prefs)
            resolveFromCache(memoryCache, key, defaultValue, encrypted)
        }
    }

    actual inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean) {
        val rawKey = if (encrypted) "encrypted_$key" else key
        dirtyKeys.add(rawKey)

        // Optimistic Update
        val toCache: Any = if (value == null) {
            NULL_SENTINEL
        } else if (encrypted) {
            json.encodeToString(serializer<T>(), value)
        } else {
            when (value) {
                is Boolean, is Int, is Long, is Float, is Double, is String -> value as Any
                else -> json.encodeToString(serializer<T>(), value)
            }
        }
        updateMemoryCache(rawKey, toCache)

        // Queue write operation for batched processing
        if (encrypted) {
            // For encrypted writes, defer encryption to background batch processor
            // This keeps the UI thread fast - encryption happens in processBatch()
            val jsonString = if (value == null) NULL_SENTINEL else json.encodeToString(serializer<T>(), value)
            val alias = fileName?.let { "$it:$key" } ?: key

            // Cache stores plaintext JSON for instant read-back
            // (resolveFromCache handles both plaintext JSON and encrypted Base64)
            updateMemoryCache(rawKey, jsonString)

            // Queue the encrypted write (encryption deferred to background)
            writeChannel.trySend(WriteOperation.Encrypted(rawKey, key, jsonString, alias))
        } else {
            // For unencrypted writes, determine the proper DataStore key type
            val storedValue: Any? = when (value) {
                null -> null
                is Boolean, is Int, is Long, is Float, is Double, is String -> value
                else -> json.encodeToString(serializer<T>(), value)
            }

            @Suppress("UNCHECKED_CAST")
            val prefKey = when (value) {
                is Boolean -> booleanPreferencesKey(key)
                is Int -> intPreferencesKey(key)
                is Long -> longPreferencesKey(key)
                is Float -> floatPreferencesKey(key)
                is Double -> doublePreferencesKey(key)
                is String -> stringPreferencesKey(key)
                else -> stringPreferencesKey(key)
            } as Preferences.Key<Any>

            // Queue the unencrypted write
            writeChannel.trySend(WriteOperation.Unencrypted(rawKey, key, storedValue, prefKey))
        }
    }

    @PublishedApi internal fun encryptedPrefKey(key: String) = stringPreferencesKey("encrypted_$key")

    suspend inline fun <reified T> putEncrypted(key: String, value: T) {
        val alias = fileName?.let { "$it:$key" } ?: key

        // Handle null values with sentinel
        val rawString = if (value == null) {
            NULL_SENTINEL
        } else {
            json.encodeToString(serializer<T>(), value)
        }

        val plainBytes = rawString.toByteArray(Charsets.UTF_8)
        val encryptedBytes = engine.encrypt(alias, plainBytes)
        val encryptedString = encodeBase64(encryptedBytes)

        dataStore.edit { prefs -> prefs[encryptedPrefKey(key)] = encryptedString }
        // IMPORTANT: Update memory cache with the RAW json string so getDirect can read it back
        updateMemoryCache("encrypted_$key", rawString)
    }

    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        if (cacheInitialized.get()) {
            return resolveFromCache(memoryCache, key, defaultValue, encrypted = true)
        }
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return resolveFromCache(memoryCache, key, defaultValue, encrypted = true)
    }

    actual suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean): T {
        return if (encrypted) getEncrypted(key, defaultValue) else getUnencrypted(key, defaultValue)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        if (cacheInitialized.get()) {
            return resolveFromCache(memoryCache, key, defaultValue, encrypted = false)
        }
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return resolveFromCache(memoryCache, key, defaultValue, encrypted = false)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal suspend inline fun <reified T> putUnencrypted(key: String, value: T) {
        // Handle null values
        if (value == null) {
            val preferencesKey = stringPreferencesKey(key)
            dataStore.edit { prefs -> prefs[preferencesKey] = NULL_SENTINEL }
            updateMemoryCache(key, NULL_SENTINEL)
            return
        }

        val preferencesKey = getUnencryptedKey(key, defaultValue = value)
        val storedValue: Any = when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> value
            else -> json.encodeToString(serializer<T>(), value)
        }
        dataStore.edit { prefs -> prefs[preferencesKey] = storedValue }
        updateMemoryCache(key, storedValue)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal fun <T> getUnencryptedKey(key: String, defaultValue: T): Preferences.Key<Any> {
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

    actual inline fun <reified T> getFlow(key: String, defaultValue: T, encrypted: Boolean): Flow<T> {
        return if (encrypted) getEncryptedFlow(key, defaultValue) else getUnencryptedFlow(key, defaultValue)
    }

    @PublishedApi internal inline fun <reified T> getUnencryptedFlow(key: String, defaultValue: T): Flow<T> {
        val preferencesKey = getUnencryptedKey(key, defaultValue)
        return dataStore.data.map { convertStoredValue(it[preferencesKey], defaultValue) }.distinctUntilChanged()
    }

    @PublishedApi internal inline fun <reified T> getEncryptedFlow(key: String, defaultValue: T): Flow<T> {
        val encryptedPrefKey = encryptedPrefKey(key)
        return dataStore.data.map { prefs ->
            val encryptedValue = prefs[encryptedPrefKey]
            if (encryptedValue == null) defaultValue
            else {
                try {
                    val alias = fileName?.let { "$it:$key" } ?: key
                    val encryptedBytes = decodeBase64(encryptedValue)
                    val plainBytes = engine.decrypt(alias, encryptedBytes)
                    val rawString = plainBytes.toString(Charsets.UTF_8)

                    // Check for null sentinel
                    if (rawString == NULL_SENTINEL) {
                        @Suppress("UNCHECKED_CAST")
                        null as T
                    } else {
                        json.decodeFromString(serializer<T>(), rawString)
                    }
                } catch (_: Exception) { defaultValue }
            }
        }.distinctUntilChanged()
    }

    actual suspend inline fun <reified T> put(key: String, value: T, encrypted: Boolean) {
        if (encrypted) {
            putEncrypted(key, value)
        } else {
            putUnencrypted(key, value)
        }
    }

    actual suspend fun delete(key: String) {
        val dataKey = stringPreferencesKey(key)
        val encryptedKey = encryptedPrefKey(key)
        dataStore.edit {
            it.remove(dataKey)
            it.remove(encryptedKey)
        }
        // Delete the encryption key using the engine
        val alias = fileName?.let { "$it:$key" } ?: key
        engine.deleteKey(alias)

        updateMemoryCache(key, null)
        updateMemoryCache("encrypted_$key", null)
    }

    actual fun deleteDirect(key: String) {
        val rawKey = key
        val encKeyName = "encrypted_$key"

        // Mark keys as dirty
        dirtyKeys.add(rawKey)
        dirtyKeys.add(encKeyName)

        // Optimistic cache update
        updateMemoryCache(key, null)
        updateMemoryCache(encKeyName, null)

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
    }

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