package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun encodeBase64Wasm(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64Wasm(encoded: String): ByteArray = Base64.decode(encoded)

/**
 * WASM/JS implementation of KSafe.
 *
 * This class manages secure key-value storage using:
 * 1. **Browser localStorage:** For persistent storage across sessions.
 * 2. **WebCrypto AES-256-GCM:** For encryption (async-only).
 * 3. **In-Memory Cache:** For providing instant, non-blocking reads to the UI.
 *
 * **Key differences from JVM/Android:**
 * - Uses `localStorage` instead of DataStore for persistence.
 * - WebCrypto is async-only, so `memoryPolicy` is always treated as `PLAIN_TEXT`.
 *   All encrypted values are decrypted at initialization and stored as plaintext in RAM.
 * - No `runBlocking` — WASM is single-threaded. Cold `getDirect` reads synchronously
 *   from localStorage for unencrypted values, or returns default for encrypted values
 *   until async init completes (but always checks memoryCache first for optimistic writes).
 * - Uses `HashMap` instead of `ConcurrentHashMap` (single-threaded).
 * - Uses `Dispatchers.Default` instead of `Dispatchers.IO`.
 *
 * **Limitations:**
 * - `localStorage` is limited to ~5-10MB per origin.
 * - Biometric authentication always returns `true`.
 * - Security and integrity checks are no-ops.
 * - Encryption keys are stored in `localStorage` (software-backed).
 *
 * @property fileName Optional namespace for the storage. Must be lower-case letters only.
 * @property lazyLoad Whether to start the background preloader immediately.
 * @property memoryPolicy Ignored on WASM — always treated as PLAIN_TEXT.
 * @property config Encryption configuration (key size, etc.)
 * @property securityPolicy Security policy for detecting threats (no-op on WASM).
 * @property plaintextCacheTtl Ignored on WASM — always PLAIN_TEXT.
 */
actual class KSafe(
    @PublishedApi internal val fileName: String? = null,
    private val lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    private val config: KSafeConfig = KSafeConfig(),
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    @PublishedApi internal val plaintextCacheTtl: Duration = 5.seconds
) {

    /**
     * Internal constructor for testing with custom encryption engine.
     *
     * Note: On WASM (single-threaded), coroutines launched in init blocks are
     * scheduled but don't execute until the current synchronous block completes.
     * So _testEngine is set before any background work actually runs.
     */
    @PublishedApi
    internal constructor(
        fileName: String? = null,
        lazyLoad: Boolean = false,
        memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        config: KSafeConfig = KSafeConfig(),
        securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
        plaintextCacheTtl: Duration = 5.seconds,
        testEngine: KSafeEncryption
    ) : this(fileName, lazyLoad, memoryPolicy, config, securityPolicy, plaintextCacheTtl) {
        _testEngine = testEngine
    }

    @PublishedApi
    internal var _testEngine: KSafeEncryption? = null

    companion object {
        private val fileNameRegex = Regex("[a-z]+")

        @PublishedApi
        internal const val NULL_SENTINEL = "__KSAFE_NULL_VALUE__"

        private const val ACCESS_POLICY_KEY = "__ksafe_access_policy__"
        private const val ACCESS_POLICY_UNLOCKED = "unlocked"
        private const val ACCESS_POLICY_DEFAULT = "default"
    }

    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must contain only lowercase letters")
        }
        validateSecurityPolicy(securityPolicy)
    }

    // --- Storage key prefixes ---
    @PublishedApi
    internal val storagePrefix: String = if (fileName != null) "ksafe_${fileName}_" else "ksafe_default_"

    // --- In-Memory Cache ---
    @PublishedApi internal val memoryCache = HashMap<String, Any>()

    // Cache initialization flag (simple Boolean — WASM is single-threaded)
    @PublishedApi internal var cacheInitialized: Boolean = false

    /** Completes when `loadCacheFromStorage()` has finished decrypting all values. */
    private val cacheReadyDeferred = CompletableDeferred<Unit>()

    @PublishedApi internal val json = Json { ignoreUnknownKeys = true }

    /**
     * Flow-based state for observing changes.
     *
     * Unlike JVM/iOS where this mirrors DataStore, on WASM this mirrors the memoryCache.
     * This ensures that optimistic writes via putDirect are immediately visible to Flow
     * observers without waiting for localStorage persistence.
     */
    @PublishedApi
    internal val stateFlow = MutableStateFlow<Map<String, Any>>(emptyMap())

    @PublishedApi
    internal val writeScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    @PublishedApi
    internal sealed class WriteOperation {
        abstract val rawKey: String

        data class Unencrypted(
            override val rawKey: String,
            val key: String,
            val value: Any?
        ) : WriteOperation()

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

    @PublishedApi
    internal val writeChannel = Channel<WriteOperation>(Channel.UNLIMITED)

    private val writeCoalesceWindowMs = 16L
    private val maxBatchSize = 50

    // Encryption engine — only used when _testEngine is null (production path)
    @PublishedApi
    internal val engine: WasmSoftwareEncryption by lazy {
        WasmSoftwareEncryption(config, storagePrefix)
    }

    // --- Unified crypto helpers ---

    /**
     * Encrypts data using either the test engine (blocking) or production engine (suspend).
     */
    @PublishedApi
    internal suspend fun doEncrypt(alias: String, data: ByteArray): ByteArray {
        val testEng = _testEngine
        return if (testEng != null) {
            testEng.encrypt(alias, data)
        } else {
            engine.encryptSuspend(alias, data)
        }
    }

    /**
     * Decrypts data using either the test engine (blocking) or production engine (suspend).
     */
    @PublishedApi
    internal suspend fun doDecrypt(alias: String, data: ByteArray): ByteArray {
        val testEng = _testEngine
        return if (testEng != null) {
            testEng.decrypt(alias, data)
        } else {
            engine.decryptSuspend(alias, data)
        }
    }

    @PublishedApi
    internal fun doDeleteKey(alias: String) {
        val testEng = _testEngine
        if (testEng != null) {
            testEng.deleteKey(alias)
        } else {
            engine.deleteKey(alias)
        }
    }

    // Track whether background collector has been started (for lazy init)
    private var collectorStarted = false

    init {
        startWriteConsumer()
    }

    init {
        if (!lazyLoad) {
            startBackgroundCollector()
        }
    }

    /**
     * Starts the background collector if it hasn't been started yet.
     * Called on first suspend access when lazyLoad=true.
     */
    @PublishedApi internal fun ensureCollectorStarted() {
        if (!collectorStarted) {
            startBackgroundCollector()
        }
    }

    private fun startWriteConsumer() {
        writeScope.launch {
            val batch = mutableListOf<WriteOperation>()

            while (true) {
                val firstOp = writeChannel.receive()
                batch.add(firstOp)

                val deadline = currentTimeMillis() + writeCoalesceWindowMs
                while (batch.size < maxBatchSize) {
                    val remaining = deadline - currentTimeMillis()
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
     * Processes a batch of write operations.
     * Encryption is performed here (in background) for encrypted writes.
     */
    private suspend fun processBatch(batch: List<WriteOperation>) {
        if (batch.isEmpty()) return

        val keysToDeleteEncryption = mutableListOf<String>()

        for (op in batch) {
            try {
                when (op) {
                    is WriteOperation.Unencrypted -> {
                        val storageKey = "$storagePrefix${op.key}"
                        if (op.value == null) {
                            safeLocalStorageSet(storageKey, NULL_SENTINEL)
                        } else {
                            safeLocalStorageSet(storageKey, op.value.toString())
                        }
                    }
                    is WriteOperation.Encrypted -> {
                        val ciphertext = doEncrypt(op.alias, op.jsonString.encodeToByteArray())
                        val storageKey = "${storagePrefix}encrypted_${op.key}"
                        safeLocalStorageSet(storageKey, encodeBase64Wasm(ciphertext))
                    }
                    is WriteOperation.Delete -> {
                        localStorageRemove("$storagePrefix${op.key}")
                        localStorageRemove("${storagePrefix}encrypted_${op.key}")
                        keysToDeleteEncryption.add(op.key)
                    }
                }
            } catch (e: Exception) {
                println("KSafe: Failed to persist key ${op.rawKey}: ${e.message}")
            }
        }

        // Delete encryption keys
        for (key in keysToDeleteEncryption) {
            try {
                val alias = fileName?.let { "$it:$key" } ?: key
                doDeleteKey(alias)
            } catch (e: Exception) {
                println("KSafe: Failed to delete encryption key $key: ${e.message}")
            }
        }
    }

    /**
     * Publishes the current memoryCache state to stateFlow for Flow observers.
     * Called whenever memoryCache changes.
     */
    @PublishedApi
    internal fun emitStateFlow() {
        stateFlow.value = HashMap(memoryCache)
    }

    private fun startBackgroundCollector() {
        if (collectorStarted) return
        collectorStarted = true

        writeScope.launch {
            migrateAccessPolicyIfNeeded()
            cleanupOrphanedCiphertext()
            loadCacheFromStorage()
        }
    }

    /**
     * Loads all localStorage entries into the in-memory cache.
     * Decrypts encrypted values at init (PLAIN_TEXT behavior on WASM).
     */
    private suspend fun loadCacheFromStorage() {
        val encryptedPrefix = "encrypted_"
        val length = localStorageLength()

        for (i in 0 until length) {
            val fullKey = localStorageKey(i) ?: continue
            if (!fullKey.startsWith(storagePrefix)) continue

            val shortKey = fullKey.removePrefix(storagePrefix)

            // Skip internal metadata keys
            if (shortKey.startsWith("__ksafe_")) continue

            val value = localStorageGet(fullKey) ?: continue

            // Don't overwrite optimistic writes from putDirect
            if (memoryCache.containsKey(shortKey)) continue

            if (shortKey.startsWith(encryptedPrefix)) {
                // Decrypt and store as plaintext
                val originalKey = shortKey.removePrefix(encryptedPrefix)
                try {
                    val alias = fileName?.let { "$it:$originalKey" } ?: originalKey
                    val encryptedBytes = decodeBase64Wasm(value)
                    val plainBytes = doDecrypt(alias, encryptedBytes)
                    memoryCache[shortKey] = plainBytes.decodeToString()
                } catch (_: Exception) { /* Skip failed decryption */ }
            } else {
                memoryCache[shortKey] = value
            }
        }

        cacheInitialized = true
        emitStateFlow()
        cacheReadyDeferred.complete(Unit)
    }

    /**
     * Detects and removes orphaned ciphertext from localStorage.
     */
    private suspend fun cleanupOrphanedCiphertext() {
        val encryptedPrefix = "encrypted_"
        val orphanedKeys = mutableListOf<String>()
        val length = localStorageLength()

        for (i in 0 until length) {
            val fullKey = localStorageKey(i) ?: continue
            if (!fullKey.startsWith(storagePrefix)) continue

            val shortKey = fullKey.removePrefix(storagePrefix)
            if (!shortKey.startsWith(encryptedPrefix)) continue
            if (shortKey.startsWith("__ksafe_")) continue

            val originalKey = shortKey.removePrefix(encryptedPrefix)
            val encryptedString = localStorageGet(fullKey) ?: continue
            val alias = fileName?.let { "$it:$originalKey" } ?: originalKey

            try {
                val ciphertext = decodeBase64Wasm(encryptedString)
                doDecrypt(alias, ciphertext)
            } catch (_: Exception) {
                orphanedKeys.add(fullKey)
            }
        }

        for (fullKey in orphanedKeys) {
            localStorageRemove(fullKey)
            val shortKey = fullKey.removePrefix(storagePrefix)
            memoryCache.remove(shortKey)
        }
    }

    /**
     * Marker-only migration for WASM. WASM has no lock concept, so no actual
     * key migration is needed — just writes the marker for consistency.
     */
    private fun migrateAccessPolicyIfNeeded() {
        val targetPolicy = if (config.requireUnlockedDevice) ACCESS_POLICY_UNLOCKED else ACCESS_POLICY_DEFAULT
        val markerKey = "$storagePrefix$ACCESS_POLICY_KEY"

        val currentPolicy = localStorageGet(markerKey)
        val effectiveCurrent = currentPolicy ?: ACCESS_POLICY_DEFAULT
        if (effectiveCurrent == targetPolicy) {
            if (currentPolicy == null) {
                safeLocalStorageSet(markerKey, targetPolicy)
            }
            return
        }

        safeLocalStorageSet(markerKey, targetPolicy)
    }

    @PublishedApi
    internal fun updateMemoryCache(key: String, value: Any?) {
        if (value == null) {
            memoryCache.remove(key)
        } else {
            memoryCache[key] = value
        }
        emitStateFlow()
    }

    @PublishedApi
    internal fun isNullSentinel(value: Any?): Boolean {
        return value == NULL_SENTINEL
    }

    @PublishedApi internal inline fun <reified T> resolveFromCache(cache: Map<String, Any>, key: String, defaultValue: T, encrypted: Boolean): T {
        val cacheKey = if (encrypted) "encrypted_$key" else key
        val cachedValue = cache[cacheKey] ?: return defaultValue

        return if (encrypted) {
            // On WASM, cache always contains plaintext (PLAIN_TEXT mode internally)
            val jsonString = cachedValue as? String ?: return defaultValue

            if (jsonString == NULL_SENTINEL) {
                @Suppress("UNCHECKED_CAST")
                return null as T
            }

            try { json.decodeFromString(serializer<T>(), jsonString) } catch (_: Exception) { defaultValue }
        } else {
            if (isNullSentinel(cachedValue)) {
                @Suppress("UNCHECKED_CAST")
                return null as T
            }
            convertStoredValue(cachedValue, defaultValue)
        }
    }

    @PublishedApi internal inline fun <reified T> convertStoredValue(storedValue: Any?, defaultValue: T): T {
        if (storedValue == null) return defaultValue

        if (isNullSentinel(storedValue)) {
            @Suppress("UNCHECKED_CAST")
            return null as T
        }

        // On WASM, all localStorage values come as Strings.
        val stringValue = storedValue as? String ?: return defaultValue

        return when (defaultValue) {
            is Boolean -> {
                stringValue.toBooleanStrictOrNull()?.let {
                    @Suppress("UNCHECKED_CAST")
                    it as T
                } ?: defaultValue
            }
            is Int -> {
                stringValue.toIntOrNull()?.let {
                    @Suppress("UNCHECKED_CAST")
                    it as T
                } ?: defaultValue
            }
            is Long -> {
                stringValue.toLongOrNull()?.let {
                    @Suppress("UNCHECKED_CAST")
                    it as T
                } ?: defaultValue
            }
            is Float -> {
                stringValue.toFloatOrNull()?.let {
                    @Suppress("UNCHECKED_CAST")
                    it as T
                } ?: defaultValue
            }
            is Double -> {
                stringValue.toDoubleOrNull()?.let {
                    @Suppress("UNCHECKED_CAST")
                    it as T
                } ?: defaultValue
            }
            is String -> {
                @Suppress("UNCHECKED_CAST")
                stringValue as T
            }
            else -> {
                // For nullable types where defaultValue is null, try direct cast first
                try {
                    @Suppress("UNCHECKED_CAST")
                    val direct = stringValue as T
                    if (direct != null) return direct
                } catch (_: ClassCastException) { /* fall through to JSON */ }

                if (stringValue == NULL_SENTINEL) {
                    @Suppress("UNCHECKED_CAST")
                    return null as T
                }
                try {
                    json.decodeFromString(serializer<T>(), stringValue)
                } catch (_: Exception) {
                    defaultValue
                }
            }
        }
    }

    // --- PUBLIC API ---

    /**
     * Suspends until the in-memory cache has been fully loaded from localStorage
     * (including async decryption of encrypted values via WebCrypto).
     *
     * Call this before accessing encrypted values via [getDirect] or compose
     * `mutableStateOf` delegates to ensure they return persisted values instead
     * of defaults.
     *
     * If `lazyLoad=true`, this also triggers the background collector.
     */
    suspend fun awaitCacheReady() {
        ensureCollectorStarted()
        cacheReadyDeferred.await()
    }

    actual inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean): T {
        // 1. ALWAYS check memoryCache first — this handles optimistic writes from putDirect
        //    even when the cache hasn't finished full initialization yet.
        val cacheKey = if (encrypted) "encrypted_$key" else key
        val cachedValue = memoryCache[cacheKey]
        if (cachedValue != null) {
            return resolveFromCache(memoryCache, key, defaultValue, encrypted)
        }

        // 2. FAST PATH: cache is fully initialized, key was not found → return default
        if (cacheInitialized) {
            return defaultValue
        }

        // 3. COLD PATH: Cache not ready yet, key not in memoryCache.
        //    For unencrypted values, read synchronously from localStorage.
        //    For encrypted values, return default (async init must complete first;
        //    can't decrypt synchronously with WebCrypto).
        if (!encrypted) {
            val storageKey = "$storagePrefix$key"
            val value = localStorageGet(storageKey)
            if (value != null) {
                memoryCache[key] = value
                return convertStoredValue(value, defaultValue)
            }
        }

        return defaultValue
    }

    actual inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean) {
        val rawKey = if (encrypted) "encrypted_$key" else key

        if (encrypted) {
            val jsonString = if (value == null) NULL_SENTINEL else json.encodeToString(serializer<T>(), value)
            val alias = fileName?.let { "$it:$key" } ?: key

            // Cache stores plaintext JSON for instant read-back (WASM always PLAIN_TEXT internally)
            updateMemoryCache(rawKey, jsonString)

            writeChannel.trySend(WriteOperation.Encrypted(rawKey, key, jsonString, alias))
        } else {
            val toCache: Any = if (value == null) {
                NULL_SENTINEL
            } else {
                when (value) {
                    is Boolean, is Int, is Long, is Float, is Double, is String -> value.toString()
                    else -> json.encodeToString(serializer<T>(), value)
                }
            }
            updateMemoryCache(rawKey, toCache)

            val storedValue: Any? = when (value) {
                null -> null
                is Boolean, is Int, is Long, is Float, is Double, is String -> value
                else -> json.encodeToString(serializer<T>(), value)
            }

            writeChannel.trySend(WriteOperation.Unencrypted(rawKey, key, storedValue))
        }
    }

    @PublishedApi internal fun encryptedPrefKey(key: String) = "encrypted_$key"

    suspend inline fun <reified T> putEncrypted(key: String, value: T) {
        val alias = fileName?.let { "$it:$key" } ?: key

        val rawString = if (value == null) {
            NULL_SENTINEL
        } else {
            json.encodeToString(serializer<T>(), value)
        }

        val plainBytes = rawString.encodeToByteArray()
        val encryptedBytes = doEncrypt(alias, plainBytes)
        val encryptedString = encodeBase64Wasm(encryptedBytes)

        // Persist to localStorage
        val storageKey = "${storagePrefix}encrypted_$key"
        safeLocalStorageSet(storageKey, encryptedString)

        // Update memory cache with plaintext (WASM always PLAIN_TEXT internally)
        updateMemoryCache("encrypted_$key", rawString)

        // Yield to allow stateIn collectors to process the emission
        yield()
    }

    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        ensureCollectorStarted()

        // Check memoryCache first (handles optimistic writes and fully-loaded cache)
        val cachedValue = memoryCache["encrypted_$key"]
        if (cachedValue != null) {
            return resolveFromCache(memoryCache, key, defaultValue, encrypted = true)
        }

        if (cacheInitialized) {
            return defaultValue
        }

        // Load from localStorage and decrypt
        val storageKey = "${storagePrefix}encrypted_$key"
        val encryptedValue = localStorageGet(storageKey) ?: return defaultValue

        try {
            val alias = fileName?.let { "$it:$key" } ?: key
            val encryptedBytes = decodeBase64Wasm(encryptedValue)
            val plainBytes = doDecrypt(alias, encryptedBytes)
            val rawString = plainBytes.decodeToString()

            // Cache it
            updateMemoryCache("encrypted_$key", rawString)

            if (rawString == NULL_SENTINEL) {
                @Suppress("UNCHECKED_CAST")
                return null as T
            }
            return json.decodeFromString(serializer<T>(), rawString)
        } catch (_: Exception) {
            return defaultValue
        }
    }

    actual suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean): T {
        return if (encrypted) getEncrypted(key, defaultValue) else getUnencrypted(key, defaultValue)
    }

    @PublishedApi internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        ensureCollectorStarted()

        // Check memoryCache first — handles optimistic writes from putDirect
        val cachedValue = memoryCache[key]
        if (cachedValue != null) {
            return resolveFromCache(memoryCache, key, defaultValue, encrypted = false)
        }

        if (cacheInitialized) {
            return defaultValue
        }

        // Read directly from localStorage
        val storageKey = "$storagePrefix$key"
        val value = localStorageGet(storageKey) ?: return defaultValue
        memoryCache[key] = value
        return convertStoredValue(value, defaultValue)
    }

    @PublishedApi internal suspend inline fun <reified T> putUnencrypted(key: String, value: T) {
        if (value == null) {
            safeLocalStorageSet("$storagePrefix$key", NULL_SENTINEL)
            updateMemoryCache(key, NULL_SENTINEL)
            yield()
            return
        }

        val storedValue = when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> value.toString()
            else -> json.encodeToString(serializer<T>(), value)
        }
        safeLocalStorageSet("$storagePrefix$key", storedValue)
        updateMemoryCache(key, storedValue)

        // Yield to allow stateIn collectors to process the emission
        yield()
    }

    actual inline fun <reified T> getFlow(key: String, defaultValue: T, encrypted: Boolean): Flow<T> {
        return if (encrypted) getEncryptedFlow(key, defaultValue) else getUnencryptedFlow(key, defaultValue)
    }

    @PublishedApi internal inline fun <reified T> getUnencryptedFlow(key: String, defaultValue: T): Flow<T> {
        return stateFlow.map { snapshot ->
            val value = snapshot[key]
            if (value == null) defaultValue
            else convertStoredValue(value, defaultValue)
        }.distinctUntilChanged()
    }

    @PublishedApi internal inline fun <reified T> getEncryptedFlow(key: String, defaultValue: T): Flow<T> {
        // On WASM, stateFlow mirrors memoryCache which contains plaintext for encrypted values.
        // So we just deserialize from JSON, no decryption needed.
        val encKey = "encrypted_$key"
        return stateFlow.map { snapshot ->
            val value = snapshot[encKey]
            if (value == null) defaultValue
            else {
                val jsonString = value as? String ?: return@map defaultValue
                if (jsonString == NULL_SENTINEL) {
                    @Suppress("UNCHECKED_CAST")
                    null as T
                } else {
                    try {
                        json.decodeFromString(serializer<T>(), jsonString)
                    } catch (_: Exception) { defaultValue }
                }
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
        localStorageRemove("$storagePrefix$key")
        localStorageRemove("${storagePrefix}encrypted_$key")

        val alias = fileName?.let { "$it:$key" } ?: key
        doDeleteKey(alias)

        updateMemoryCache(key, null)
        updateMemoryCache("encrypted_$key", null)
    }

    actual fun deleteDirect(key: String) {
        updateMemoryCache(key, null)
        updateMemoryCache("encrypted_$key", null)

        writeChannel.trySend(WriteOperation.Delete(key, key))
    }

    actual suspend fun clearAll() {
        // Remove all localStorage entries with our prefix
        val keysToRemove = mutableListOf<String>()
        val length = localStorageLength()
        for (i in 0 until length) {
            val key = localStorageKey(i) ?: continue
            if (key.startsWith(storagePrefix)) {
                keysToRemove.add(key)
            }
        }
        for (key in keysToRemove) {
            localStorageRemove(key)
        }

        memoryCache.clear()
        emitStateFlow()
    }

    actual suspend fun verifyBiometric(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?
    ): Boolean {
        // No biometric hardware in browser
        return true
    }

    actual fun verifyBiometricDirect(
        reason: String,
        authorizationDuration: BiometricAuthorizationDuration?,
        onResult: (Boolean) -> Unit
    ) {
        // No biometric hardware in browser
        onResult(true)
    }

    actual fun clearBiometricAuth(scope: String?) {
        // No biometric hardware in browser - nothing to clear
    }
}

/**
 * Wrapper for localStorage.setItem that catches QuotaExceededError.
 * localStorage is limited to ~5-10MB per origin.
 */
@PublishedApi
internal fun safeLocalStorageSet(key: String, value: String) {
    try {
        localStorageSet(key, value)
    } catch (e: Exception) {
        throw IllegalStateException(
            "KSafe: localStorage quota exceeded. " +
            "localStorage is limited to ~5-10MB per origin. " +
            "Consider reducing stored data or using fewer keys.",
            e
        )
    }
}

/**
 * Returns current time in milliseconds.
 * Uses `Date.now()` via JS interop.
 */
@OptIn(kotlin.js.ExperimentalWasmJsInterop::class)
@JsFun("() => { return BigInt(Date.now()); }")
private external fun currentTimeMillis(): Long
