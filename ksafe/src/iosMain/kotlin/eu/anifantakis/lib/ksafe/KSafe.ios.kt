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
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.providers.cryptokit.CryptoKit
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import okio.Path.Companion.toPath
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSArray
import platform.Foundation.NSDictionary
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSURL
import platform.Foundation.NSUserDomainMask
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitAll
import platform.Security.kSecReturnAttributes
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random
import kotlin.concurrent.AtomicReference

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@PublishedApi
@OptIn(ExperimentalEncodingApi::class)
internal fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

/**
 * iOS implementation of KSafe.
 *
 * This class manages secure key-value storage using:
 * 1. **Jetpack DataStore:** For storing encrypted values (or plain values) on disk.
 * 2. **iOS Keychain Services:** For generating and storing AES-256 cryptographic keys securely.
 * 3. **Atomic Hot Cache:** For providing instant, non-blocking reads to the UI.
 * 4. **Hybrid Loading:** Preloads data in background, but falls back to blocking load if accessed early.
 *
 * @property fileName Optional namespace for the storage file. Must be lower-case letters only.
 * @property lazyLoad Whether to start the background preloader immediately.
 * @property memoryPolicy Whether to decrypt and store values in RAM, or keep them encrypted in RAM for additional security
 * @property config Encryption configuration (key size, etc.)
 * @property securityPolicy Security policy for detecting jailbroken devices, debuggers, etc.
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

    companion object Companion {
        // we intentionally don't allow "." to avoid path traversal vulnerabilities
        private val fileNameRegex = Regex("[a-z]+")
        private const val SERVICE_NAME = "eu.anifantakis.ksafe"
        @PublishedApi
        internal const val KEY_PREFIX = "eu.anifantakis.ksafe"
        private const val INSTALLATION_ID_KEY = "ksafe_installation_id"

        /**
         * Checks if running on iOS Simulator (no biometric hardware available).
         */
        @OptIn(ExperimentalForeignApi::class)
        private fun isSimulator(): Boolean {
            val environment = NSProcessInfo.processInfo.environment
            return environment["SIMULATOR_UDID"] != null
        }

        /**
         * Sentinel value used to represent null in storage.
         * This allows distinguishing between "key not found" and "key exists with null value".
         */
        @PublishedApi
        internal const val NULL_SENTINEL = "__KSAFE_NULL_VALUE__"
    }

    // Encryption engine - uses test engine if provided, or creates default IosKeychainEncryption
    @PublishedApi
    internal val engine: KSafeEncryption by lazy {
        _testEngine ?: IosKeychainEncryption(
            config = config,
            serviceName = SERVICE_NAME
        )
    }

    init {
        if (fileName != null) {
            if (!fileName.matches(fileNameRegex)) {
                throw IllegalArgumentException("File name must contain only lowercase letters.")
            }
        }

        // Validate security policy (may throw SecurityViolationException)
        validateSecurityPolicy(securityPolicy)
    }

    /**
     * **Synchronization Mutex.**
     *
     * Unlike Android which uses `synchronized` blocks, iOS K/N requires a Coroutine Mutex
     * to safely coordinate the Main Thread (calling `getDirect`) and the Background Thread
     * (calling `updateCache`). This prevents the "Race Condition" where the background thread
     * tries to generate keys while the main thread reads them.
     */
    private val mutex = Mutex()

    /**
     * **Thread-Safe In-Memory Cache (Hot State).**
     *
     * Holds a map of pre-decrypted values. Uses AtomicReference with optimized updates.
     */
    @PublishedApi internal val memoryCache = AtomicReference<MutableMap<String, Any>>(mutableMapOf())

    /**
     * **Cache Initialization Flag.**
     *
     * Tracks whether the cache has been populated from DataStore.
     */
    @PublishedApi internal val cacheInitialized = AtomicReference(false)

    /**
     * **Dirty Keys Tracker.**
     *
     * A thread-safe set of keys currently being written to disk.
     * Uses AtomicReference with copy-on-write for Kotlin/Native thread safety.
     */
    private val dirtyKeys = AtomicReference<Set<String>>(emptySet())
    @PublishedApi internal val json = Json { ignoreUnknownKeys = true }

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
    internal val writeScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

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
            val keyId: String
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
                val now = (platform.CoreFoundation.CFAbsoluteTimeGetCurrent() + 978307200.0) * 1000
                val deadline = now + writeCoalesceWindowMs
                while (batch.size < maxBatchSize) {
                    val currentMs = (platform.CoreFoundation.CFAbsoluteTimeGetCurrent() + 978307200.0) * 1000
                    val remaining = (deadline - currentMs).toLong()
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

        // Collect keys that need Keychain deletion
        val keysToDeleteFromKeychain = mutableListOf<String>()

        // Pre-encrypt all encrypted operations (done in background, not UI thread)
        val encryptedData = mutableMapOf<String, ByteArray>()
        for (op in batch) {
            if (op is WriteOperation.Encrypted) {
                val ciphertext = engine.encrypt(op.keyId, op.jsonString.encodeToByteArray())
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
                        keysToDeleteFromKeychain.add(op.key)
                    }
                }
            }
        }

        // Delete encryption keys from Keychain (outside of DataStore edit)
        for (key in keysToDeleteFromKeychain) {
            val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
            engine.deleteKey(keyId)
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

    // Create DataStore using a file in the app's Documents directory.
    @OptIn(ExperimentalForeignApi::class)
    @PublishedApi internal val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.createWithPath(
        scope = CoroutineScope(Dispatchers.Default + SupervisorJob()),
        produceFile = {
            val docDir: NSURL? = NSFileManager.defaultManager.URLForDirectory(
                directory = NSDocumentDirectory,
                inDomain = NSUserDomainMask,
                appropriateForURL = null,
                create = true,  // Changed to true to ensure directory exists
                error = null
            )
            requireNotNull(docDir).path.plus(
                fileName?.let { "/eu_anifantakis_ksafe_datastore_${fileName}.preferences_pb" }
                    ?: "/eu_anifantakis_ksafe_datastore.preferences_pb"
            ).toPath()
        }
    )

    // Track if cleanup has been performed
    @PublishedApi
    internal var cleanupPerformed = false

    init {
        // Force registration of the Apple provider.
        registerAppleProvider()
        forceAesGcmRegistration()

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

    private fun registerAppleProvider() {
        // This explicitly registers the Apple provider with the default CryptographyProvider.
        CryptographyProvider.CryptoKit
    }

    private fun forceAesGcmRegistration() {
        // Dummy reference to ensure AES.GCM is not stripped.
        @Suppress("UNUSED_VARIABLE", "unused")
        val dummy = AES.GCM
    }

    /**
     * Ensures cleanup is performed once. This is called lazily on first access.
     * Protected by Mutex to be thread-safe.
     */
    suspend fun ensureCleanupPerformed() {
        mutex.withLock {
            ensureCleanupPerformedLocked()
        }
    }

    /**
     * Internal locked cleanup logic.
     * Called when the Mutex is already held (e.g., from [updateCache]).
     */
    private suspend fun ensureCleanupPerformedLocked() {
        if (!cleanupPerformed) {
            cleanupPerformed = true
            try {
                cleanupOrphanedKeychainEntries()
            } catch (e: Exception) {
                // Log error but don't crash the app
                println("KSafe: Failed to cleanup orphaned keychain entries: ${e.message}")
            }
        }
    }

    /**
     * Gets or creates a unique installation ID. This helps us detect fresh installs.
     */
    private suspend fun getOrCreateInstallationId(): String {
        val installationIdKey = stringPreferencesKey(INSTALLATION_ID_KEY)
        val currentId = dataStore.data.map { it[installationIdKey] }.first()

        if (currentId != null) {
            return currentId
        }

        // Generate new installation ID
        val newId = generateInstallationId()
        dataStore.edit { preferences ->
            preferences[installationIdKey] = newId
        }

        return newId
    }

    private fun generateInstallationId(): String {
        val bytes = ByteArray(16)
        Random.nextBytes(bytes)
        return encodeBase64(bytes)
    }

    /**
     * Clean up orphaned Keychain entries from previous installations
     */
    private suspend fun cleanupOrphanedKeychainEntries() {
        @Suppress("UnusedVariable", "unused")
        val installationId = getOrCreateInstallationId()

        // Get all keys that have markers in DataStore
        val validKeys = mutableSetOf<String>()
        val preferences = dataStore.data.first()

        preferences.asMap().forEach { (key, _) ->
            if (key.name.startsWith(fileName?.let { "${fileName}_" } ?: "encrypted_")) {
                val keyId = key.name.removePrefix(fileName?.let { "${fileName}_" } ?: "encrypted_")
                validKeys.add(keyId)
            }
        }

        // Find and remove all Keychain entries that don't have corresponding data
        removeOrphanedKeychainKeys(validKeys)
    }

    /**
     * Remove Keychain entries that don't have corresponding encrypted data in DataStore
     */
    @OptIn(ExperimentalForeignApi::class)
    private fun removeOrphanedKeychainKeys(validKeys: Set<String>) {
        val basePrefix = listOfNotNull(KEY_PREFIX, fileName).joinToString(".")
        val prefixWithDelimiter = "$basePrefix."

        memScoped {
            // Query for all our Keychain items
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                null,
                null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
                CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(SERVICE_NAME))
                CFDictionarySetValue(this, kSecReturnAttributes, kCFBooleanTrue)
                CFDictionarySetValue(this, kSecMatchLimit, kSecMatchLimitAll)
            }

            val resultRef = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, resultRef.ptr)
            CFRelease(query as CFTypeRef?)

            if (status == errSecSuccess) {
                val items = CFBridgingRelease(resultRef.value) as? NSArray
                items?.let { array ->
                    for (i in 0 until array.count.toInt()) {
                        val dict = array.objectAtIndex(i.toULong()) as? NSDictionary
                        val account = dict?.objectForKey(kSecAttrAccount as Any) as? String
                        if (account != null && account.startsWith(prefixWithDelimiter)) {
                            val keyId = account.removePrefix(prefixWithDelimiter)

                            // FIX: Don't delete keys belonging to other KSafe instances
                            if (fileName == null && keyId.contains('.')) continue

                            if (keyId !in validKeys) deleteKeychainKey(keyId)
                        }
                    }
                }
            }
        }
    }

    /**
     * Thread-safe helper to update specific keys in the memory cache.
     * Uses direct O(1) put/remove operations on the underlying map.
     */
    /**
     * Thread-safe cache update using copy-on-write with AtomicReference.
     * This is critical for Kotlin/Native where HashMap is not thread-safe.
     */
    @PublishedApi
    internal fun updateMemoryCache(key: String, value: Any?) {
        while (true) {
            val current = memoryCache.value
            val updated = current.toMutableMap() // Always creates a NEW map
            if (value == null) {
                updated.remove(key)
            } else {
                updated[key] = value
            }
            if (memoryCache.compareAndSet(current, updated)) break
        }
    }

    /**
     * Updates the [memoryCache] based on the raw [Preferences] from DataStore.
     *
     * **Thread-Safe Copy-on-Write Design:**
     * Builds a new map and atomically swaps it using AtomicReference.
     * This is required for Kotlin/Native where HashMap is not thread-safe.
     *
     * The dirty keys mechanism ensures that optimistic writes from [putDirect] are not
     * overwritten by stale data from DataStore during the write window.
     *
     * Cleanup is handled separately via [ensureCleanupPerformed] which has its own mutex.
     */
    @PublishedApi
    internal suspend fun updateCache(prefs: Preferences) {
        // Ensure cleanup runs once (has its own mutex protection)
        ensureCleanupPerformed()

        val prefsMap = prefs.asMap()
        val encryptedPrefix = fileName?.let { "${fileName}_" } ?: "encrypted_"

        // Snapshot of dirty keys - atomic read for thread safety
        val currentDirty: Set<String> = dirtyKeys.value

        // Build a new cache map (copy-on-write for thread safety)
        val currentCache = memoryCache.value
        val newCache = currentCache.toMutableMap()
        val validKeys = mutableSetOf<String>()

        for ((key, value) in prefsMap) {
            val keyName = key.name

            // Dirty Check: If a local write was pending at snapshot time,
            // skip updating from disk (preserve optimistic value).
            if (currentDirty.contains(keyName)) {
                validKeys.add(keyName)
                continue
            }

            if (keyName.startsWith(encryptedPrefix)) {
                validKeys.add(keyName)
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
                    // SECURITY MODE: Store raw Ciphertext in RAM.
                    newCache[keyName] = value
                } else {
                    // PERFORMANCE MODE: Decrypt now, store Plaintext.
                    val originalKey = keyName.removePrefix(encryptedPrefix)
                    val encryptedString = value as? String
                    if (encryptedString != null) {
                        try {
                            val ciphertext = decodeBase64(encryptedString)
                            val keyId = listOfNotNull(KEY_PREFIX, fileName, originalKey).joinToString(".")
                            val decryptedBytes = engine.decrypt(keyId, ciphertext)
                            newCache[keyName] = decryptedBytes.decodeToString()
                        } catch (e: IllegalStateException) {
                            // Re-throw security-critical errors (device locked)
                            if (e.message?.contains("device is locked") == true ||
                                e.message?.contains("Keychain") == true) {
                                throw e
                            }
                            // Other errors ignored during cache init
                        } catch (_: Exception) { /* Ignore other failures */ }
                    }
                }
            } else if (!keyName.startsWith("ksafe_")) {
                validKeys.add(keyName)
                newCache[keyName] = value
            }
        }

        // Also preserve all dirty keys as valid (they're being written)
        validKeys.addAll(currentDirty)

        // Remove keys that no longer exist in DataStore (except dirty ones)
        val keysToRemove = newCache.keys.filter { it !in validKeys }
        keysToRemove.forEach { newCache.remove(it) }

        // Atomically swap the cache using compareAndSet loop
        while (true) {
            val current = memoryCache.value
            // Merge any changes that happened during our processing
            val merged = current.toMutableMap()
            for ((k, v) in newCache) {
                // Only update if not dirty (dirty keys have fresher data)
                if (k !in currentDirty) {
                    merged[k] = v
                }
            }
            // Remove keys that should be removed (but preserve dirty ones)
            for (k in keysToRemove) {
                if (k !in currentDirty) {
                    merged.remove(k)
                }
            }
            if (memoryCache.compareAndSet(current, merged)) break
        }

        // Mark cache as initialized
        cacheInitialized.value = true
    }

    /**
     * Adds a key to the dirty set. Thread-safe via copy-on-write with AtomicReference.
     */
    @PublishedApi
    internal fun addDirtyKey(key: String) {
        while (true) {
            val current = dirtyKeys.value
            val updated = current + key
            if (dirtyKeys.compareAndSet(current, updated)) break
        }
    }



    /**
     * Checks if the given value represents a stored null (using the sentinel).
     */
    @PublishedApi
    internal fun isNullSentinel(value: Any?): Boolean {
        return value == NULL_SENTINEL
    }

    @PublishedApi internal inline fun <reified T> resolveFromCache(cache: Map<String, Any>, key: String, defaultValue: T, encrypted: Boolean): T {
        val cacheKey = if (encrypted) (fileName?.let { "${fileName}_$key" } ?: "encrypted_$key") else key
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
                        val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
                        val decryptedBytes = engine.decrypt(keyId, ciphertext)
                        val candidateJson = decryptedBytes.decodeToString()

                        // Try deserializing to verify it's valid JSON
                        // If this succeeds, we accept it as the decrypted value
                        // Check for null sentinel first
                        if (candidateJson == NULL_SENTINEL) {
                            @Suppress("UNCHECKED_CAST")
                            deserializedValue = null as T
                        } else {
                            deserializedValue = json.decodeFromString(serializer<T>(), candidateJson)
                        }
                        success = true
                    }
                } catch (e: IllegalStateException) {
                    // Re-throw security-critical errors (device locked, keychain inaccessible)
                    if (e.message?.contains("device is locked") == true ||
                        e.message?.contains("Keychain") == true) {
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
            // Check for null sentinel first
            if (isNullSentinel(cachedValue)) {
                @Suppress("UNCHECKED_CAST")
                return null as T
            }
            convertStoredValue(cachedValue, defaultValue)
        }
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal inline fun <reified T> convertStoredValue(storedValue: Any?, defaultValue: T): T {
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
                // For nullable types where defaultValue is null, we need special handling
                if (defaultValue == null) {
                    val jsonString = storedValue as? String ?: return defaultValue
                    if (jsonString == NULL_SENTINEL) return null as T
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

    // ----- Unencrypted Storage Functions -----
    @Suppress("UNCHECKED_CAST")
    @PublishedApi
    internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        if (cacheInitialized.value) {
            return resolveFromCache(memoryCache.value, key, defaultValue, encrypted = false)
        }

        ensureCleanupPerformed() // Thread-safe cleanup

        val prefs = dataStore.data.first()
        updateCache(prefs) // Waits for Mutex
        return resolveFromCache(memoryCache.value, key, defaultValue, encrypted = false)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi
    internal suspend inline fun <reified T> putUnencrypted(key: String, value: T) {
        ensureCleanupPerformed() // Thread-safe cleanup

        // Handle null values
        if (value == null) {
            val preferencesKey = stringPreferencesKey(key)
            dataStore.edit { preferences ->
                preferences[preferencesKey] = NULL_SENTINEL
            }
            updateMemoryCache(key, NULL_SENTINEL)
            return
        }

        val preferencesKey: Preferences.Key<Any> = when (value) {
            is Boolean -> booleanPreferencesKey(key)
            is Number -> {
                when {
                    value is Int || (value is Long && value in Int.MIN_VALUE..Int.MAX_VALUE) ->
                        intPreferencesKey(key)

                    value is Long -> longPreferencesKey(key)
                    value is Float -> floatPreferencesKey(key)
                    value is Double -> doublePreferencesKey(key)
                    else -> stringPreferencesKey(key)
                }
            }

            is String -> stringPreferencesKey(key)
            else -> stringPreferencesKey(key)
        } as Preferences.Key<Any>

        val storedValue: Any = when (value) {
            is Boolean -> value
            is Number -> {
                when {
                    value is Int || (value is Long && value in Int.MIN_VALUE..Int.MAX_VALUE) -> value.toInt()
                    else -> value
                }
            }

            is String -> value
            else -> json.encodeToString(serializer<T>(), value)
        }

        dataStore.edit { preferences ->
            preferences[preferencesKey] = storedValue
        }

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

    // ----- Encryption Helpers -----

    @PublishedApi
    internal fun encryptedPrefKey(key: String) =
        stringPreferencesKey(fileName?.let { "${fileName}_$key" } ?: "encrypted_$key")

    /**
     * Deletes a key from iOS Keychain.
     * Used by cleanup logic to remove orphaned keys.
     */
    @OptIn(ExperimentalForeignApi::class)
    @PublishedApi
    internal fun deleteKeychainKey(keyId: String) {
        val account = listOfNotNull(KEY_PREFIX, fileName, keyId).joinToString(".")

        memScoped {
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                null,
                null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassGenericPassword)
                CFDictionarySetValue(this, kSecAttrService, CFBridgingRetain(SERVICE_NAME))
                CFDictionarySetValue(this, kSecAttrAccount, CFBridgingRetain(account))
            }

            SecItemDelete(query)
            CFRelease(query as CFTypeRef?)
        }
    }

    suspend fun storeEncryptedData(key: String, data: ByteArray) {
        val encoded = encodeBase64(data)
        dataStore.edit { preferences ->
            preferences[encryptedPrefKey(key)] = encoded
        }
    }

    suspend inline fun <reified T> putEncrypted(key: String, value: T) {
        ensureCleanupPerformed()

        // Handle null values with sentinel
        val jsonString = if (value == null) {
            NULL_SENTINEL
        } else {
            json.encodeToString(serializer<T>(), value)
        }
        val plaintext = jsonString.encodeToByteArray()

        // Encrypt using the engine
        val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
        val ciphertext = engine.encrypt(keyId, plaintext)

        storeEncryptedData(key, ciphertext)

        // Sync cache:
        // If ENCRYPTED policy, store Ciphertext (Base64) so reads hit the Keychain.
        // If PLAIN_TEXT policy, store JSON for instant reads.
        val rawKey = fileName?.let { "${fileName}_$key" } ?: "encrypted_$key"
        val cacheValue = if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
            encodeBase64(ciphertext)
        } else {
            jsonString
        }
        updateMemoryCache(rawKey, cacheValue)
    }

    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        if (cacheInitialized.value) {
            return resolveFromCache(memoryCache.value, key, defaultValue, encrypted = true)
        }

        ensureCleanupPerformed()

        val prefs = dataStore.data.first()
        updateCache(prefs) // Waits for Mutex
        return resolveFromCache(memoryCache.value, key, defaultValue, encrypted = true)
    }

    actual suspend inline fun <reified T> get(
        key: String,
        defaultValue: T,
        encrypted: Boolean
    ): T {
        return if (encrypted) {
            getEncrypted(key, defaultValue)
        } else {
            getUnencrypted(key, defaultValue)
        }
    }

    actual inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean): T {
        // FAST PATH (Cache Ready)
        // If background preload finished, return instantly.
        if (cacheInitialized.value) {
            return resolveFromCache(memoryCache.value, key, defaultValue, encrypted)
        }

        // FALLBACK PATH (Cache Not Ready)
        // "Abandon" waiting for the background job and fetch/build it ourselves immediately.
        // This blocks the thread ONLY for the first call.
        return runBlocking {
            // Optimization: Check if background thread finished while we were entering runBlocking
            if (cacheInitialized.value) {
                return@runBlocking resolveFromCache(memoryCache.value, key, defaultValue, encrypted)
            }

            val prefs = dataStore.data.first()
            updateCache(prefs) // Waits for Mutex to ensure safety
            resolveFromCache(memoryCache.value, key, defaultValue, encrypted)
        }
    }

    @Suppress("UNCHECKED_CAST")
    @OptIn(ExperimentalCoroutinesApi::class)
    @PublishedApi
    internal inline fun <reified T> getUnencryptedFlow(key: String, defaultValue: T): Flow<T> {
        // Ensure cleanup on first access
        writeScope.launch {
            ensureCleanupPerformed()
        }
        val preferencesKey = getUnencryptedKey(key, defaultValue)

        return dataStore.data.mapLatest { preferences ->
            val storedValue = preferences[preferencesKey]
            convertStoredValue(storedValue, defaultValue)
        }.distinctUntilChanged()
    }


    @OptIn(ExperimentalCoroutinesApi::class)
    @PublishedApi
    internal inline fun <reified T> getEncryptedFlow(key: String, defaultValue: T): Flow<T> {
        val encryptedPrefKey = encryptedPrefKey(key)

        return dataStore.data
            .onStart { ensureCleanupPerformed() }
            .map { preferences ->
                val encryptedValue = preferences[encryptedPrefKey]
                if (encryptedValue == null) {
                    defaultValue
                } else {
                    try {
                        val ciphertext = decodeBase64(encryptedValue)

                        // Decrypt using the engine
                        val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
                        val decryptedBytes = engine.decrypt(keyId, ciphertext)
                        val jsonString = decryptedBytes.decodeToString()

                        // Check for null sentinel
                        if (jsonString == NULL_SENTINEL) {
                            @Suppress("UNCHECKED_CAST")
                            null as T
                        } else {
                            json.decodeFromString(serializer<T>(), jsonString)
                        }
                    } catch (e: IllegalStateException) {
                        // Re-throw security-critical errors (device locked, keychain inaccessible)
                        if (e.message?.contains("device is locked") == true ||
                            e.message?.contains("Keychain") == true) {
                            throw e
                        }
                        // Other IllegalStateExceptions return default
                        defaultValue
                    } catch (_: Exception) {
                        // If decryption fails, return default value
                        defaultValue
                    }
                }
            }.distinctUntilChanged()
    }

    @Suppress("unused")
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

    actual inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean) {
        val rawKey = if (encrypted) (fileName?.let { "${fileName}_$key" } ?: "encrypted_$key") else key
        addDirtyKey(rawKey)

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
            val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")

            // Cache stores plaintext JSON for instant read-back
            // (resolveFromCache handles both plaintext JSON and encrypted Base64)
            updateMemoryCache(rawKey, jsonString)

            // Queue the encrypted write (encryption deferred to background)
            writeChannel.trySend(WriteOperation.Encrypted(rawKey, key, jsonString, keyId))
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

        // Delete the encryption key using the engine
        val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
        engine.deleteKey(keyId)

        val encKeyName = fileName?.let { "${fileName}_$key" } ?: "encrypted_$key"
        updateMemoryCache(key, null)
        updateMemoryCache(encKeyName, null)
    }

    /**
     * Deletes a value from DataStore without using coroutines.
     * This function is **non-blocking**.
     *
     * @param key The key of the value to delete.
     */
    @Suppress("unused")
    actual fun deleteDirect(key: String) {
        val rawKey = key
        val encKeyName = fileName?.let { "${fileName}_$key" } ?: "encrypted_$key"

        // Mark keys as dirty
        addDirtyKey(rawKey)
        addDirtyKey(encKeyName)

        // Optimistic cache update
        updateMemoryCache(key, null)
        updateMemoryCache(encKeyName, null)

        // Queue delete operation for batched processing
        writeChannel.trySend(WriteOperation.Delete(rawKey, key))
    }

    /**
     * Clear all data including Keychain entries.
     * Useful for complete cleanup or testing.
     */
    @Suppress("unused")
    actual suspend fun clearAll() {
        // Get all encrypted keys before clearing
        val encryptedKeys = mutableSetOf<String>()
        val preferences = dataStore.data.first()

        preferences.asMap().forEach { (key, _) ->
            if (key.name.startsWith(fileName?.let { "${fileName}_" } ?: "encrypted_")) {
                val keyId =
                    key.name.removePrefix(fileName?.let { "${fileName}_" } ?: "encrypted_")
                encryptedKeys.add(keyId)
            }
        }

        // Clear all DataStore preferences
        dataStore.edit { it.clear() }

        // Delete all associated encryption keys using the engine
        encryptedKeys.forEach { keyId ->
            val keyIdentifier = listOfNotNull(KEY_PREFIX, fileName, keyId).joinToString(".")
            engine.deleteKey(keyIdentifier)
        }

        // Thread-safe clear using atomic swap
        memoryCache.value = mutableMapOf()
    }

    /**
     * Gets the current time in milliseconds.
     * CFAbsoluteTimeGetCurrent returns seconds since Jan 1, 2001.
     * We add the difference to Unix epoch (978307200 seconds).
     */
    @OptIn(ExperimentalForeignApi::class)
    private fun currentTimeMillis(): Long {
        val cfTime = platform.CoreFoundation.CFAbsoluteTimeGetCurrent()
        // CFAbsoluteTime epoch is Jan 1, 2001. Unix epoch is Jan 1, 1970.
        // Difference is 978307200 seconds
        return ((cfTime + 978307200.0) * 1000).toLong()
    }

    /**
     * Atomically updates the biometric auth session for a scope.
     */
    private fun updateBiometricSession(scope: String, timestamp: Long) {
        while (true) {
            val current = biometricAuthSessions.value
            val updated = current + (scope to timestamp)
            if (biometricAuthSessions.compareAndSet(current, updated)) break
        }
    }

    /**
     * Verifies biometric authentication using iOS LocalAuthentication framework.
     *
     * @param reason The reason string to display
     * @param authorizationDuration Optional duration configuration for caching successful authentication.
     */
    actual suspend fun verifyBiometric(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?
    ): Boolean {
        // Check if we're still within the authorized duration for this scope
        if (authorizationDuration != null && authorizationDuration.duration > 0) {
            val scope = authorizationDuration.scope ?: ""
            val sessions = biometricAuthSessions.value
            val lastAuth = sessions[scope] ?: 0L
            val now = currentTimeMillis()
            if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
                return true // Still authorized for this scope, skip biometric prompt
            }
        }

        // In simulator, always return true (no biometric hardware)
        if (isSimulator()) {
            if (authorizationDuration != null) {
                val scope = authorizationDuration.scope ?: ""
                updateBiometricSession(scope, currentTimeMillis())
            }
            return true
        }

        return kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
            verifyBiometricDirectInternal(reason) { success ->
                if (success && authorizationDuration != null) {
                    val scope = authorizationDuration.scope ?: ""
                    updateBiometricSession(scope, currentTimeMillis())
                }
                continuation.resumeWith(Result.success(success))
            }
        }
    }

    /**
     * Verifies biometric authentication using iOS LocalAuthentication framework (non-blocking).
     *
     * @param reason The reason string to display
     * @param authorizationDuration Optional duration configuration for caching successful authentication.
     * @param onResult Callback with true if authentication succeeded, false otherwise
     */
    actual fun verifyBiometricDirect(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
        onResult: (Boolean) -> Unit
    ) {
        // Dispatch to Main thread for consistency with Android implementation
        CoroutineScope(Dispatchers.Main).launch {
            // Check if we're still within the authorized duration for this scope
            if (authorizationDuration != null && authorizationDuration.duration > 0) {
                val scope = authorizationDuration.scope ?: ""
                val sessions = biometricAuthSessions.value
                val lastAuth = sessions[scope] ?: 0L
                val now = currentTimeMillis()
                if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
                    onResult(true) // Still authorized for this scope, skip biometric prompt
                    return@launch
                }
            }

            // In simulator, always return true (no biometric hardware)
            if (isSimulator()) {
                if (authorizationDuration != null) {
                    val scope = authorizationDuration.scope ?: ""
                    updateBiometricSession(scope, currentTimeMillis())
                }
                onResult(true)
                return@launch
            }

            // Perform actual biometric authentication
            // Note: verifyBiometricDirectInternal handles its own main thread dispatch for the callback,
            // but since we are already in a Main scope launch, it's fine.
            // However, verifyBiometricDirectInternal is private and takes a callback.
            // To keep things clean, let's inline the logic or delegate cleanly.
            
            val context = platform.LocalAuthentication.LAContext()
            val policy = platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics

            context.evaluatePolicy(policy, localizedReason = reason) { success, _ ->
                // Callback from LAContext is on a background thread, so we must dispatch back to Main
                CoroutineScope(Dispatchers.Main).launch {
                    if (success && authorizationDuration != null) {
                        val scope = authorizationDuration.scope ?: ""
                        updateBiometricSession(scope, currentTimeMillis())
                    }
                    onResult(success)
                }
            }
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
            biometricAuthSessions.value = emptyMap()
        } else {
            // Clear specific scope
            while (true) {
                val current = biometricAuthSessions.value
                val updated = current - scope
                if (biometricAuthSessions.compareAndSet(current, updated)) break
            }
        }
    }

    /**
     * Internal biometric verification without duration caching.
     */
    private fun verifyBiometricDirectInternal(reason: String, onResult: (Boolean) -> Unit) {
        val context = platform.LocalAuthentication.LAContext()
        val policy = platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics

        context.evaluatePolicy(policy, localizedReason = reason) { success, _ ->
            CoroutineScope(Dispatchers.Main).launch {
                onResult(success)
            }
        }
    }
}

// iOS: non-inline helper to get the AES-GCM algorithm instance.
fun obtainAesGcm(): AES.GCM {
    return CryptographyProvider.CryptoKit.get(AES.GCM)
}