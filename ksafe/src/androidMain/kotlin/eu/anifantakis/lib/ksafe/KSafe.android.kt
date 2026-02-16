package eu.anifantakis.lib.ksafe

import android.content.Context
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
import androidx.datastore.preferences.preferencesDataStoreFile
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
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.ComparableTimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

/**
 * Android implementation of KSafe.
 *
 * This class manages secure key-value storage using:
 * 1. **Jetpack DataStore:** For storing encrypted values (or plain values) on disk.
 * 2. **Android Keystore System:** For generating and storing AES-256 cryptographic keys securely in hardware.
 * 3. **Atomic Hot Cache:** For providing instant, non-blocking reads to the UI.
 *
 * @property context Android Context used to create the DataStore file.
 * @property fileName Optional namespace for the storage file. Must be lower-case letters only.
 * @property lazyLoad Whether to start the background preloader immediately.
 * @property memoryPolicy Whether to decrypt and store values in RAM, or keep them encrypted in RAM for additional security
 * @property config Encryption configuration (key size, etc.)
 * @property securityPolicy Security policy for detecting rooted devices, debuggers, etc.
 */
actual class KSafe(
    private val context: Context,
    @PublishedApi internal val fileName: String? = null,
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
        context: Context,
        fileName: String? = null,
        lazyLoad: Boolean = false,
        memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        config: KSafeConfig = KSafeConfig(),
        securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
        plaintextCacheTtl: Duration = 5.seconds,
        testEngine: KSafeEncryption
    ) : this(context, fileName, lazyLoad, memoryPolicy, config, securityPolicy, plaintextCacheTtl) {
        _testEngine = testEngine
    }

    // Internal injection hook for testing
    @PublishedApi
    internal var _testEngine: KSafeEncryption? = null

    companion object Companion {
        // we intentionally don't allow "." to avoid path traversal vulnerabilities
        private val fileNameRegex = Regex("[a-z]+")
        const val KEY_ALIAS_PREFIX = "eu.anifantakis.ksafe"

        /**
         * Sentinel value used to represent null in storage.
         * This allows distinguishing between "key not found" and "key exists with null value".
         */
        @PublishedApi
        internal const val NULL_SENTINEL = "__KSAFE_NULL_VALUE__"

        private const val ACCESS_POLICY_KEY = "__ksafe_access_policy__"
        private const val ACCESS_POLICY_UNLOCKED = "unlocked"
        private const val ACCESS_POLICY_DEFAULT = "default"

        private val dataStoreCache = ConcurrentHashMap<String, DataStore<Preferences>>()
    }

    // Encryption engine - uses test engine if provided, or creates default AndroidKeystoreEncryption
    @PublishedApi
    internal val engine: KSafeEncryption by lazy {
        _testEngine ?: AndroidKeystoreEncryption(config)
    }

    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must contain only lowercase letters")
        }

        // Initialize BiometricHelper for auto-biometric support
        val app = context.applicationContext as? android.app.Application
        if (app != null) {
            BiometricHelper.init(app)
        }

        // Set application context for security checks
        SecurityChecker.applicationContext = context.applicationContext

        // Validate security policy (may throw SecurityViolationException)
        validateSecurityPolicy(securityPolicy)
    }

    @PublishedApi
    internal val json = Json { ignoreUnknownKeys = true }

    // Create a DataStore for our preferences (cached per file to avoid "multiple active instances" crash on DI re-init).
    @PublishedApi
    internal val dataStore: DataStore<Preferences> = dataStoreCache.getOrPut(
        fileName ?: "default"
    ) {
        PreferenceDataStoreFactory.create(
            scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
            produceFile = {
                val file =
                    fileName?.let { "eu_anifantakis_ksafe_datastore_${fileName}" } ?: "eu_anifantakis_ksafe_datastore"
                context.preferencesDataStoreFile(file)
            }
        )
    }

    /**
     * **Thread-Safe In-Memory Cache (Hot State).**
     *
     * Holds a map of pre-decrypted values: `Map<Key, Value>`.
     * Uses ConcurrentHashMap for O(1) per-key operations instead of copy-on-write.
     * This enables [getDirect] to return immediately without blocking for disk I/O.
     */
    @PublishedApi
    internal val memoryCache = ConcurrentHashMap<String, Any>()

    /**
     * **Short-lived plaintext cache for [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE].**
     *
     * Stores recently-decrypted values with an expiry deadline.
     * Only populated when [memoryPolicy] is [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE].
     */
    @PublishedApi
    internal class CachedPlaintext(val value: String, val expiresAt: ComparableTimeMark)

    @PublishedApi
    internal val plaintextCache = ConcurrentHashMap<String, CachedPlaintext>()

    /**
     * **Cache Initialization Flag.**
     *
     * Tracks whether the cache has been populated from DataStore.
     * Used to detect cold start vs hot cache scenarios in [getDirect].
     */
    @PublishedApi
    internal val cacheInitialized = AtomicBoolean(false)

    /**
     * **Dirty Keys Tracker.**
     *
     * A thread-safe set of keys currently being written to disk.
     * This prevents the background DataStore observer from overwriting our optimistic
     * in-memory updates with stale data from disk during the write window.
     * Uses ConcurrentHashMap.newKeySet() for O(1) add/remove operations.
     */
    @PublishedApi
    internal val dirtyKeys: MutableSet<String> = ConcurrentHashMap.newKeySet()

    /**
     * Map of scope -> timestamp for biometric authorization sessions.
     * Each scope maintains its own authorization timestamp.
     */
    @PublishedApi
    internal val biometricAuthSessions = AtomicReference<Map<String, Long>>(emptyMap())

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
            val keyAlias: String
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

        // Collect keys that need Keystore deletion
        val keysToDeleteFromKeystore = mutableListOf<String>()

        // Pre-encrypt all encrypted operations (done in background, not UI thread)
        val encryptedData = mutableMapOf<String, ByteArray>()
        for (op in batch) {
            if (op is WriteOperation.Encrypted) {
                val ciphertext = engine.encrypt(op.keyAlias, op.jsonString.encodeToByteArray())
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
                        keysToDeleteFromKeystore.add(op.key)
                    }
                }
            }
        }

        // Delete encryption keys from Keystore (outside of DataStore edit)
        for (key in keysToDeleteFromKeystore) {
            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
            engine.deleteKey(keyAlias)
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

    /**
     * Adds a key to the dirty set. O(1) operation with ConcurrentHashMap.
     */
    @PublishedApi
    internal fun addDirtyKey(key: String) {
        dirtyKeys.add(key)
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
     * After app reinstall (Android Auto Backup restores DataStore but NOT Keystore keys),
     * encrypted entries become permanently undecryptable. This method probes each encrypted
     * entry and removes those whose keys are gone.
     *
     * Entries that fail with "device is locked" are skipped (temporary failure, retry next launch).
     */
    private suspend fun cleanupOrphanedCiphertext() {
        val prefs = dataStore.data.first()
        val encryptedPrefix = "encrypted_"
        val orphanedKeys = mutableListOf<String>()

        for ((key, value) in prefs.asMap()) {
            val keyName = key.name
            if (!keyName.startsWith(encryptedPrefix)) continue
            if (keyName.startsWith("__ksafe_")) continue

            val originalKey = keyName.removePrefix(encryptedPrefix)
            val encryptedString = value as? String ?: continue
            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, originalKey).joinToString(".")

            try {
                val ciphertext = decodeBase64(encryptedString)
                engine.decrypt(keyAlias, ciphertext)
            } catch (e: Exception) {
                val msg = e.message ?: ""
                if (msg.contains("device is locked", ignoreCase = true)) {
                    continue
                }
                orphanedKeys.add(keyName)
            }
        }

        if (orphanedKeys.isNotEmpty()) {
            dataStore.edit { mutablePrefs ->
                for (keyName in orphanedKeys) {
                    mutablePrefs.remove(stringPreferencesKey(keyName))
                }
            }
            for (keyName in orphanedKeys) {
                memoryCache.remove(keyName)
            }
        }
    }

    /**
     * One-time migration of encryption key access policy.
     *
     * When [KSafeConfig.requireUnlockedDevice] changes, existing Android Keystore keys
     * need to be re-created with the new policy. This method:
     * 1. Reads the current policy marker from DataStore
     * 2. If it matches the target, returns immediately (no-op)
     * 3. If `requireUnlockedDevice = true`: decrypts all encrypted values with the old key,
     *    deletes the old Keystore key, re-encrypts with a new key that has
     *    `setUnlockedDeviceRequired(true)`, and writes the updated ciphertext atomically
     * 4. Writes the policy marker on success so migration doesn't repeat
     */
    private suspend fun migrateAccessPolicyIfNeeded() {
        val targetPolicy = if (config.requireUnlockedDevice) ACCESS_POLICY_UNLOCKED else ACCESS_POLICY_DEFAULT
        val markerKey = stringPreferencesKey(ACCESS_POLICY_KEY)

        // Check current marker.
        // Treat null (pre-1.5.0, no marker) the same as ACCESS_POLICY_DEFAULT
        // to avoid unnecessary re-encryption on upgrade when requireUnlockedDevice=false.
        // Without this, the migration would delete+recreate every Keystore key,
        // opening a window where concurrent getDirect calls fail (key temporarily gone).
        val currentPolicy = dataStore.data.first()[markerKey]
        val effectiveCurrent = currentPolicy ?: ACCESS_POLICY_DEFAULT
        if (effectiveCurrent == targetPolicy) {
            // Still write the marker if it was null (first launch after upgrade)
            if (currentPolicy == null) {
                dataStore.edit { it[markerKey] = targetPolicy }
            }
            return
        }

        // Both directions require re-encryption on Android:
        // - false→true: old key has no lock restriction, new key needs setUnlockedDeviceRequired(true)
        // - true→false: old key has setUnlockedDeviceRequired(true), new key needs no restriction
        //
        // Two-phase approach for failure safety:
        //   Phase 1: Decrypt all values (keys untouched). If any fails → abort (retry next launch).
        //   Phase 2: Delete old keys + re-encrypt. If any fails → stop immediately.
        // This ensures we never delete a key unless we've already proven we can decrypt its data.
        val prefs = dataStore.data.first()
        val encryptedPrefix = "encrypted_"

        // Phase 1: Decrypt all values first — no Keystore mutations
        val decryptedData = mutableMapOf<String, Pair<String, ByteArray>>() // keyName → (keyAlias, plaintext)
        for ((key, value) in prefs.asMap()) {
            val keyName = key.name
            if (!keyName.startsWith(encryptedPrefix)) continue
            if (keyName.startsWith("__ksafe_")) continue

            val originalKey = keyName.removePrefix(encryptedPrefix)
            val encryptedString = value as? String ?: continue
            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, originalKey).joinToString(".")

            try {
                val ciphertext = decodeBase64(encryptedString)
                val plaintext = engine.decrypt(keyAlias, ciphertext)
                decryptedData[keyName] = Pair(keyAlias, plaintext)
            } catch (_: Exception) {
                // Decrypt failed (device locked, key invalidated, etc.)
                // Abort migration entirely — all old keys remain intact.
                return
            }
        }

        // Phase 2: Delete old keys + re-encrypt with new key properties
        val reEncrypted = mutableMapOf<String, String>()
        for ((keyName, pair) in decryptedData) {
            val (keyAlias, plaintext) = pair
            try {
                engine.deleteKey(keyAlias)
                val newCiphertext = engine.encrypt(keyAlias, plaintext)
                reEncrypted[keyName] = encodeBase64(newCiphertext)
            } catch (_: Exception) {
                // Encrypt failed after key deletion — stop immediately to limit damage.
                // Marker is NOT written, so migration retries on next launch.
                // Already-deleted keys in this loop are lost (Keystore has no undo),
                // but stopping early preserves the remaining keys.
                return
            }
        }

        // All keys migrated successfully — persist atomically
        dataStore.edit { mutablePrefs ->
            for ((keyName, newValue) in reEncrypted) {
                mutablePrefs[stringPreferencesKey(keyName)] = newValue
            }
            mutablePrefs[markerKey] = targetPolicy
        }
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
        // ConcurrentHashMap iterators can throw NoSuchElementException in rare cases
        val currentDirty: Set<String> = try {
            HashSet(dirtyKeys)
        } catch (e: NoSuchElementException) {
            // Concurrent modification during copy - very rare edge case
            // Return empty set; dirty keys will be checked on next update cycle
            emptySet()
        }

        // Build set of keys that should exist based on DataStore
        val validKeys = mutableSetOf<String>()

        for ((key, value) in prefsMap) {
            val keyName = key.name

            // Skip internal KSafe metadata keys (e.g., migration markers)
            if (keyName.startsWith("__ksafe_")) continue

            // Dirty Check: If a local write was pending at snapshot time,
            // skip updating from disk (preserve optimistic value).
            // Use the SNAPSHOT for this check to avoid race conditions.
            // NOTE: We do NOT clear dirty flags here because the DataStore snapshot
            // might contain OLD data, not the data from our pending write.
            // NOTE: Dirty flags are intentionally kept permanently — see processBatch for rationale.
            if (currentDirty.contains(keyName)) {
                validKeys.add(keyName)
                continue
            }

            // Handle Encrypted Entries
            if (keyName.startsWith(encryptedPrefix)) {
                validKeys.add(keyName)
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                    // SECURITY MODE: Store the raw ciphertext string in RAM.
                    memoryCache[keyName] = value
                } else {
                    // PERFORMANCE MODE: Decrypt now, store plaintext in RAM.
                    val originalKey = keyName.removePrefix(encryptedPrefix)
                    val encryptedString = value as? String
                    if (encryptedString != null) {
                        try {
                            val ciphertext = decodeBase64(encryptedString)
                            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, originalKey).joinToString(".")
                            val decryptedBytes = engine.decrypt(keyAlias, ciphertext)
                            memoryCache[keyName] = decryptedBytes.decodeToString()
                        } catch (_: Exception) { }
                    }
                }
            }
            // Handle Unencrypted Entries
            else if (!keyName.startsWith("ksafe_")) {
                validKeys.add(keyName)
                memoryCache[keyName] = value
            }
        }

        // Also preserve all dirty keys as valid (they're being written)
        validKeys.addAll(currentDirty)

        // Remove keys that no longer exist in DataStore (except dirty ones)
        // Use try-catch to handle concurrent modification during iteration
        try {
            val keysToRemove = memoryCache.keys.filter { it !in validKeys && !dirtyKeys.contains(it) }
            keysToRemove.forEach { memoryCache.remove(it) }
        } catch (e: NoSuchElementException) {
            // Concurrent modification - skip cleanup this cycle
        }

        // Mark cache as initialized
        cacheInitialized.set(true)
    }

    /**
     * Thread-safe helper to update specific keys in the memory cache.
     * Uses ConcurrentHashMap's O(1) put/remove operations - no copy needed!
     */
    @PublishedApi
    internal fun updateMemoryCache(rawKeyName: String, value: Any?) {
        if (value == null) {
            memoryCache.remove(rawKeyName)
        } else {
            memoryCache[rawKeyName] = value
        }
    }

    // ----- Storage Helpers -----

    /**
     * Checks if the given value represents a stored null (using the sentinel).
     */
    @PublishedApi
    internal fun isNullSentinel(value: Any?): Boolean {
        return value == NULL_SENTINEL
    }

    @PublishedApi
    internal inline fun <reified T> resolveFromCache(cache: Map<String, Any>, key: String, defaultValue: T, encrypted: Boolean): T {
        // Determine internal key format used in cache (isomorphic to disk keys)
        val cacheKey = if (encrypted) "encrypted_$key" else key
        val cachedValue = cache[cacheKey] ?: return defaultValue

        return if (encrypted) {
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
                        val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
                        val decryptedBytes = engine.decrypt(keyAlias, ciphertext)
                        val candidateJson = decryptedBytes.decodeToString()

                        // Try deserializing to verify it's valid JSON
                        // If this succeeds, we accept it as the decrypted value
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
                } catch (e: IllegalStateException) {
                    // Re-throw security-critical errors (device locked, Keystore inaccessible)
                    if (e.message?.contains("device is locked") == true ||
                        e.message?.contains("Keystore") == true) {
                        throw e
                    }
                    // Other IllegalStateExceptions fall through to plaintext fallback
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
            // Unencrypted values are stored as primitives or JSON strings (for objects)
            // Check for null sentinel first
            if (isNullSentinel(cachedValue)) {
                @Suppress("UNCHECKED_CAST")
                return null as T
            }
            convertStoredValue(cachedValue, defaultValue)
        }
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi
    internal inline fun <reified T> convertStoredValue(storedValue: Any?, defaultValue: T): T {
        if (storedValue == null) return defaultValue

        // Check for null sentinel
        if (isNullSentinel(storedValue)) {
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

    // ----- Public API implementation -----

    actual inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean): T {
        // 1. FAST PATH: Cache is ready (Background preload finished) -> Return instantly
        if (cacheInitialized.get()) {
            return resolveFromCache(memoryCache, key, defaultValue, encrypted)
        }

        // 2. FALLBACK PATH: Cache not ready -> Block to fetch immediately (Cold Start)
        // This only happens if accessed before the background loader finishes.
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

        // 1. Mark key as dirty to prevent overwrite by background observer
        addDirtyKey(rawKey)

        // 2. Optimistic update + queue write operation
        if (encrypted) {
            // Single serialization for encrypted writes
            val jsonString = if (value == null) NULL_SENTINEL else json.encodeToString(serializer<T>(), value)
            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")

            // Cache stores plaintext JSON for instant read-back
            // (resolveFromCache handles both plaintext JSON and encrypted Base64)
            updateMemoryCache(rawKey, jsonString)

            // For TIMED_CACHE, also populate the plaintext cache
            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                plaintextCache[rawKey] = CachedPlaintext(jsonString, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
            }

            // Queue the encrypted write (encryption deferred to background)
            writeChannel.trySend(WriteOperation.Encrypted(rawKey, key, jsonString, keyAlias))
        } else {
            // Optimistic update for unencrypted writes
            val toCache: Any = if (value == null) {
                NULL_SENTINEL
            } else {
                when (value) {
                    is Boolean, is Int, is Long, is Float, is Double, is String -> value as Any
                    else -> json.encodeToString(serializer<T>(), value)
                }
            }
            updateMemoryCache(rawKey, toCache)

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

    // ----- Encryption Helpers -----
    @PublishedApi
    internal fun encryptedPrefKey(key: String) = stringPreferencesKey("encrypted_$key")

    suspend fun storeEncryptedData(key: String, data: ByteArray) {
        val encoded = encodeBase64(data)
        dataStore.edit { preferences ->
            preferences[encryptedPrefKey(key)] = encoded
        }
    }

    suspend inline fun <reified T> putEncrypted(key: String, value: T) {
        // Handle null values with sentinel
        val jsonString = if (value == null) {
            NULL_SENTINEL
        } else {
            json.encodeToString(serializer<T>(), value)
        }

        // Use encryption engine (switch to Default dispatcher — encryption is CPU-bound)
        val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
        val ciphertext = withContext(Dispatchers.Default) {
            engine.encrypt(keyAlias, jsonString.encodeToByteArray())
        }

        storeEncryptedData(key, ciphertext)

        // Sync cache

        // Optimistic Update:
        // If ENCRYPTED or TIMED_CACHE policy, store Ciphertext (Base64). If PLAIN, store JSON.
        val cacheValue = if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
            encodeBase64(ciphertext)
        } else {
            jsonString
        }
        updateMemoryCache("encrypted_$key", cacheValue)

        // For TIMED_CACHE, also populate the plaintext cache (we already have the plaintext)
        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
            plaintextCache["encrypted_$key"] = CachedPlaintext(jsonString, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
        }
    }

    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        // Check cache first
        if (cacheInitialized.get()) {
            return withContext(Dispatchers.Default) {
                resolveFromCache(memoryCache, key, defaultValue, encrypted = true)
            }
        }

        // Fallback to disk (ensure cache is populated)
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return withContext(Dispatchers.Default) {
            resolveFromCache(memoryCache, key, defaultValue, encrypted = true)
        }
    }

    actual suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean): T {
        return if (encrypted) {
            getEncrypted(key, defaultValue)
        } else {
            getUnencrypted(key, defaultValue)
        }
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi
    internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        // Check cache first
        if (cacheInitialized.get()) {
            return resolveFromCache(memoryCache, key, defaultValue, encrypted = false)
        }

        // Fallback to disk
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return resolveFromCache(memoryCache, key, defaultValue, encrypted = false)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi
    internal suspend inline fun <reified T> putUnencrypted(key: String, value: T) {
        // Handle null values
        if (value == null) {
            val preferencesKey = stringPreferencesKey(key)
            dataStore.edit { preferences ->
                preferences[preferencesKey] = NULL_SENTINEL
            }
            updateMemoryCache(key, NULL_SENTINEL)
            return
        }

        val preferencesKey = getUnencryptedKey(key, defaultValue = value)

        val storedValue: Any = when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> value
            else -> json.encodeToString(serializer<T>(), value)
        }

        dataStore.edit { preferences ->
            preferences[preferencesKey] = storedValue
        }

        // Update cache
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

    @Suppress("UNCHECKED_CAST")
    @PublishedApi
    internal inline fun <reified T> getUnencryptedFlow(key: String, defaultValue: T): Flow<T> {
        val preferencesKey = getUnencryptedKey(key, defaultValue)
        return dataStore.data.map { preferences ->
            val storedValue = preferences[preferencesKey]
            convertStoredValue(storedValue, defaultValue)
        }.distinctUntilChanged()
    }

    @PublishedApi
    internal inline fun <reified T> getEncryptedFlow(key: String, defaultValue: T): Flow<T> {
        val encryptedPrefKey = encryptedPrefKey(key)

        return dataStore.data
            .map { preferences ->
                val encryptedValue = preferences[encryptedPrefKey]
                if (encryptedValue == null) {
                    defaultValue
                } else {
                    try {
                        val ciphertext = decodeBase64(encryptedValue)
                        val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
                        val decryptedBytes = engine.decrypt(keyAlias, ciphertext)
                        val jsonString = decryptedBytes.decodeToString()

                        // Check for null sentinel
                        if (jsonString == NULL_SENTINEL) {
                            @Suppress("UNCHECKED_CAST")
                            null as T
                        } else {
                            json.decodeFromString(serializer<T>(), jsonString)
                        }
                    } catch (e: IllegalStateException) {
                        // Re-throw security-critical errors (device locked)
                        if (e.message?.contains("device is locked") == true ||
                            e.message?.contains("Keystore") == true) {
                            throw e
                        }
                        defaultValue
                    } catch (_: Exception) {
                        defaultValue
                    }
                }
            }
            .distinctUntilChanged()
    }

    actual inline fun <reified T> getFlow(
        key: String,
        defaultValue: T,
        encrypted: Boolean
    ): Flow<T> {
        return if (encrypted) {
            getEncryptedFlow(key, defaultValue)
        } else {
            getUnencryptedFlow(key, defaultValue)
        }
    }

    actual suspend inline fun <reified T> put(key: String, value: T, encrypted: Boolean) {
        if (encrypted) {
            putEncrypted(key, value)
        } else {
            putUnencrypted(key, value)
        }
    }

    /**
     * Deletes a value from DataStore.
     *
     * @param key The key of the value to delete.
     */
    actual suspend fun delete(key: String) {
        val dataKey = stringPreferencesKey(key)
        val encryptedKey = encryptedPrefKey(key)

        dataStore.edit { preferences ->
            preferences.remove(dataKey)
            preferences.remove(encryptedKey)
        }

        // Delete the corresponding encryption key using the engine
        val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
        engine.deleteKey(keyAlias)

        // Update cache
        updateMemoryCache(key, null)
        updateMemoryCache("encrypted_$key", null)
        plaintextCache.remove(key)
        plaintextCache.remove("encrypted_$key")
    }

    /**
     * Deletes a value from DataStore without using coroutines.
     * This function is **non-blocking**.
     *
     * @param key The key of the value to delete.
     */
    actual fun deleteDirect(key: String) {
        // Mark both possible keys as dirty
        addDirtyKey(key)
        addDirtyKey("encrypted_$key")

        // Optimistic update
        updateMemoryCache(key, null)
        updateMemoryCache("encrypted_$key", null)
        plaintextCache.remove(key)
        plaintextCache.remove("encrypted_$key")

        // Queue delete operation
        writeChannel.trySend(WriteOperation.Delete(key, key))
    }

    /**
     * Clear all data including Keystore entries.
     * Useful for complete cleanup or testing.
     * Note: On Android, Keystore entries are automatically deleted on app uninstall.
     */
    actual suspend fun clearAll() {
        // Get all encrypted keys before clearing
        val encryptedKeys = mutableSetOf<String>()
        val preferences = dataStore.data.first()

        preferences.asMap().forEach { (key, _) ->
            if (key.name.startsWith("encrypted_")) {
                val keyId = key.name.removePrefix("encrypted_")
                encryptedKeys.add(keyId)
            }
        }

        // Clear all DataStore preferences
        dataStore.edit { it.clear() }

        // Delete all associated encryption keys using the engine
        encryptedKeys.forEach { keyId ->
            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, keyId).joinToString(".")
            engine.deleteKey(keyAlias)
        }

        // Clear cache
        memoryCache.clear()
        plaintextCache.clear()
    }

    /**
     * Atomically updates the biometric auth session for a scope.
     */
    private fun updateBiometricSession(scope: String, timestamp: Long) {
        while (true) {
            val current = biometricAuthSessions.get()
            val updated = current + (scope to timestamp)
            if (biometricAuthSessions.compareAndSet(current, updated)) break
        }
    }

    /**
     * Verifies biometric authentication on Android using BiometricPrompt.
     *
     * This method automatically finds the current Activity and shows the biometric prompt.
     * The BiometricHelper is initialized automatically when KSafe is created.
     *
     * @param reason The reason string to display (used as prompt subtitle)
     * @param authorizationDuration Optional duration configuration for caching successful authentication.
     * @return true if authentication succeeded, false if it failed or was cancelled
     */
    actual suspend fun verifyBiometric(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?
    ): Boolean {
        // Check if we're still within the authorized duration for this scope
        if (authorizationDuration != null && authorizationDuration.duration > 0) {
            val scope = authorizationDuration.scope ?: ""
            val sessions = biometricAuthSessions.get()
            val lastAuth = sessions[scope] ?: 0L
            val now = System.currentTimeMillis()
            if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
                return true // Still authorized for this scope, skip biometric prompt
            }
        }

        return try {
            // Update subtitle with the provided reason
            BiometricHelper.authenticate(reason)
            // Update auth time for this scope on success (if duration caching is enabled)
            if (authorizationDuration != null) {
                val scope = authorizationDuration.scope ?: ""
                updateBiometricSession(scope, System.currentTimeMillis())
            }
            true
        } catch (e: BiometricAuthException) {
            println("KSafe: Biometric authentication failed - ${e.message}")
            false
        } catch (e: BiometricActivityNotFoundException) {
            println("KSafe: Biometric Activity not found - ${e.message}")
            false
        } catch (e: Exception) {
            println("KSafe: Unexpected biometric error - ${e.message}")
            false
        }
    }

    /**
     * Verifies biometric authentication on Android (non-blocking callback version).
     *
     * @param reason The reason string to display (used as prompt subtitle)
     * @param authorizationDuration Optional duration configuration for caching successful authentication.
     * @param onResult Callback with true if authentication succeeded, false otherwise
     */
    actual fun verifyBiometricDirect(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
        onResult: (Boolean) -> Unit
    ) {
        CoroutineScope(Dispatchers.Main + SupervisorJob()).launch {
            val result = verifyBiometric(reason, authorizationDuration)
            onResult(result)
        }
    }

    /**
     * Clears cached biometric authorization for a specific scope or all scopes.
     *
     * @param scope The scope to clear. If null, clears ALL cached authorizations.
     */
    actual fun clearBiometricAuth(scope: String?) {
        if (scope == null) {
            // Clear all sessions
            biometricAuthSessions.set(emptyMap())
        } else {
            // Clear specific scope
            while (true) {
                val current = biometricAuthSessions.get()
                val updated = current - scope
                if (biometricAuthSessions.compareAndSet(current, updated)) break
            }
        }
    }
}