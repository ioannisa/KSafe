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
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun encodeBase64Web(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64Web(encoded: String): ByteArray = Base64.decode(encoded)

/**
 * Shared web (wasmJs + js) implementation of KSafe.
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
 * - No `runBlocking` — browser JS is single-threaded. Cold `getDirect` reads
 *   synchronously from localStorage for unencrypted values, or returns default
 *   for encrypted values until async init completes (but always checks memoryCache
 *   first for optimistic writes).
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
 * @property memoryPolicy Ignored on web — always treated as PLAIN_TEXT.
 * @property config Encryption configuration (key size, etc.)
 * @property securityPolicy Security policy for detecting threats (no-op on web).
 * @property plaintextCacheTtl Ignored on web — always PLAIN_TEXT.
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
     * Note: On web (single-threaded), coroutines launched in init blocks are
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
        // Must start with a lowercase letter; may also contain digits and underscores.
        private val fileNameRegex = Regex("[a-z][a-z0-9_]*")

        @PublishedApi
        internal const val NULL_SENTINEL = "__KSAFE_NULL_VALUE__"

    }

    actual val deviceKeyStorages: Set<KSafeKeyStorage> = setOf(KSafeKeyStorage.SOFTWARE)
    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores")
        }
        validateSecurityPolicy(securityPolicy)
    }

    // --- Storage key prefixes ---
    @PublishedApi
    internal val storagePrefix: String = if (fileName != null) "ksafe_${fileName}_" else "ksafe_default_"

    @PublishedApi
    internal fun valueRawKey(key: String): String = KeySafeMetadataManager.valueRawKey(key)

    @PublishedApi
    internal fun defaultEncryptedMode(): KSafeWriteMode =
        KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)

    @PublishedApi
    internal fun valueStorageKey(key: String): String = "$storagePrefix${valueRawKey(key)}"

    @PublishedApi
    internal fun metaStorageKey(key: String): String = "$storagePrefix${KeySafeMetadataManager.metadataRawKey(key)}"

    @PublishedApi
    internal fun legacyEncryptedStorageKey(key: String): String =
        "$storagePrefix${KeySafeMetadataManager.legacyEncryptedRawKey(key)}"

    @PublishedApi
    internal fun legacyPlainStorageKey(key: String): String = "$storagePrefix$key"

    @PublishedApi
    internal fun legacyMetaStorageKey(key: String): String =
        "$storagePrefix${KeySafeMetadataManager.legacyProtectionRawKey(key)}"

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
    internal fun removeAllLegacyStorageKeys(key: String) {
        localStorageRemove(legacyPlainStorageKey(key))
        localStorageRemove(legacyEncryptedStorageKey(key))
        localStorageRemove(legacyMetaStorageKey(key))
    }

    // --- In-Memory Cache ---
    @PublishedApi internal val memoryCache = HashMap<String, Any>()
    @PublishedApi internal val protectionMap = HashMap<String, String>()

    // Cache initialization flag (simple Boolean — web is single-threaded)
    @PublishedApi internal var cacheInitialized: Boolean = false

    /** Completes when `loadCacheFromStorage()` has finished decrypting all values. */
    private val cacheReadyDeferred = CompletableDeferred<Unit>()

    @PublishedApi internal val json: Json = config.json

    /**
     * Flow-based state for observing changes.
     *
     * Unlike JVM/iOS where this mirrors DataStore, on web this mirrors the memoryCache.
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
            val alias: String,
            val requireUnlockedDevice: Boolean = false
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
    internal val engine: WebSoftwareEncryption by lazy {
        WebSoftwareEncryption(config, storagePrefix)
    }

    // --- Unified crypto helpers ---

    /**
     * Encrypts data using either the test engine (blocking) or production engine (suspend).
     */
    @PublishedApi
    internal suspend fun doEncrypt(
        alias: String,
        data: ByteArray,
        requireUnlockedDevice: Boolean? = null
    ): ByteArray {
        val testEng = _testEngine
        return if (testEng != null) {
            testEng.encrypt(alias, data, requireUnlockedDevice = requireUnlockedDevice)
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

                val deadline = currentTimeMillisWeb() + writeCoalesceWindowMs
                while (batch.size < maxBatchSize) {
                    val remaining = deadline - currentTimeMillisWeb()
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
                        val storageKey = valueStorageKey(op.key)
                        if (op.value == null) {
                            safeLocalStorageSet(storageKey, NULL_SENTINEL)
                        } else {
                            safeLocalStorageSet(storageKey, op.value.toString())
                        }
                        safeLocalStorageSet(metaStorageKey(op.key), protectionToMetaJson(null))
                        removeAllLegacyStorageKeys(op.key)
                    }
                    is WriteOperation.Encrypted -> {
                        val ciphertext = doEncrypt(
                            alias = op.alias,
                            data = op.jsonString.encodeToByteArray(),
                            requireUnlockedDevice = op.requireUnlockedDevice
                        )
                        val storageKey = valueStorageKey(op.key)
                        safeLocalStorageSet(storageKey, encodeBase64Web(ciphertext))
                        safeLocalStorageSet(
                            metaStorageKey(op.key),
                            protectionToMetaJson(
                                protection = KSafeProtection.DEFAULT,
                                requireUnlockedDevice = op.requireUnlockedDevice
                            )
                        )
                        removeAllLegacyStorageKeys(op.key)
                    }
                    is WriteOperation.Delete -> {
                        localStorageRemove(valueStorageKey(op.key))
                        localStorageRemove(metaStorageKey(op.key))
                        removeAllLegacyStorageKeys(op.key)
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
     * Decrypts encrypted values at init (PLAIN_TEXT behavior on web).
     */
    private suspend fun loadCacheFromStorage() {
        val length = localStorageLength()
        val existingMetadata = HashMap(protectionMap)
        val entries = mutableListOf<Pair<String, String?>>()
        for (i in 0 until length) {
            val fullKey = localStorageKey(i) ?: continue
            if (!fullKey.startsWith(storagePrefix)) continue
            val shortKey = fullKey.removePrefix(storagePrefix)
            entries += shortKey to localStorageGet(fullKey)
        }
        val protectionByKey = KeySafeMetadataManager.collectMetadata(entries).toMutableMap()

        // Pass 2: values
        for (i in 0 until length) {
            val fullKey = localStorageKey(i) ?: continue
            if (!fullKey.startsWith(storagePrefix)) continue
            val shortKey = fullKey.removePrefix(storagePrefix)
            val value = localStorageGet(fullKey) ?: continue

            val classified = KeySafeMetadataManager.classifyStorageEntry(
                rawKey = shortKey,
                legacyEncryptedPrefix = KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX,
                encryptedCacheKeyForUser = { userKey -> KeySafeMetadataManager.legacyEncryptedRawKey(userKey) },
                stagedMetadata = protectionByKey,
                existingMetadata = existingMetadata
            ) ?: continue

            val userKey = classified.userKey
            val cacheKey = classified.cacheKey
            val isEncrypted = classified.encrypted

            if (!protectionByKey.containsKey(userKey)) {
                protectionByKey[userKey] = if (isEncrypted) "DEFAULT" else "NONE"
            }

            // Don't overwrite optimistic writes from putDirect
            if (memoryCache.containsKey(cacheKey)) continue

            if (isEncrypted) {
                try {
                    val alias = fileName?.let { "$it:$userKey" } ?: userKey
                    val encryptedBytes = decodeBase64Web(value)
                    val plainBytes = doDecrypt(alias, encryptedBytes)
                    memoryCache[cacheKey] = plainBytes.decodeToString()
                } catch (e: Exception) {
                    // Decryption failed — skip this entry (will use default on read)
                }
            } else {
                memoryCache[cacheKey] = value
            }
        }

        protectionMap.clear()
        for ((k, v) in protectionByKey) {
            protectionMap[k] = KeySafeMetadataManager.extractProtectionLiteral(v)
        }

        cacheInitialized = true
        emitStateFlow()
        cacheReadyDeferred.complete(Unit)
    }

    /**
     * Detects and removes orphaned ciphertext from localStorage.
     */
    private suspend fun cleanupOrphanedCiphertext() {
        val orphanedKeys = mutableListOf<String>()
        val length = localStorageLength()
        val protectionByKey = mutableMapOf<String, KSafeProtection>()

        for (i in 0 until length) {
            val fullKey = localStorageKey(i) ?: continue
            if (!fullKey.startsWith(storagePrefix)) continue
            val shortKey = fullKey.removePrefix(storagePrefix)
            val value = localStorageGet(fullKey) ?: continue
            when {
                shortKey.startsWith(KeySafeMetadataManager.META_PREFIX) && shortKey.endsWith(KeySafeMetadataManager.META_SUFFIX) -> {
                    val userKey = shortKey
                        .removePrefix(KeySafeMetadataManager.META_PREFIX)
                        .removeSuffix(KeySafeMetadataManager.META_SUFFIX)
                    KeySafeMetadataManager.parseProtection(value)?.let { protectionByKey[userKey] = it }
                }
                KeySafeMetadataManager.tryExtractLegacyProtectionKey(shortKey) != null -> {
                    val userKey = KeySafeMetadataManager.tryExtractLegacyProtectionKey(shortKey) ?: continue
                    if (!protectionByKey.containsKey(userKey)) {
                        KeySafeMetadataManager.parseProtection(value)?.let { protectionByKey[userKey] = it }
                    }
                }
            }
        }

        for (i in 0 until length) {
            val fullKey = localStorageKey(i) ?: continue
            if (!fullKey.startsWith(storagePrefix)) continue

            val shortKey = fullKey.removePrefix(storagePrefix)
            // Preserve legacy encrypted entries to avoid destructive cleanup on upgrades.
            if (shortKey.startsWith(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX)) continue
            if (!shortKey.startsWith(KeySafeMetadataManager.VALUE_PREFIX)) continue

            val originalKey = shortKey.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
            val protection = protectionByKey[originalKey]
            if (protection == null) continue

            val encryptedString = localStorageGet(fullKey) ?: continue
            val alias = fileName?.let { "$it:$originalKey" } ?: originalKey

            try {
                val ciphertext = decodeBase64Web(encryptedString)
                doDecrypt(alias, ciphertext)
            } catch (e: Exception) {
                val msg = e.message ?: ""
                if (msg.contains("No encryption key found", ignoreCase = true) ||
                    msg.contains("key not found", ignoreCase = true)) {
                    orphanedKeys.add(fullKey)
                }
            }
        }

        for (fullKey in orphanedKeys) {
            localStorageRemove(fullKey)
            val shortKey = fullKey.removePrefix(storagePrefix)
            val originalKey = shortKey.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
            memoryCache.remove(originalKey)
            memoryCache.remove(KeySafeMetadataManager.legacyEncryptedRawKey(originalKey))
        }
    }

    /** Web has no lock-based key accessibility concept. */
    private fun migrateAccessPolicyIfNeeded() = Unit

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

    @PublishedApi internal inline fun <reified T> resolveFromCache(cache: Map<String, Any>, key: String, defaultValue: T, protection: KSafeProtection?): T {
        @Suppress("UNCHECKED_CAST")
        return resolveFromCacheRaw(cache, key, defaultValue, protection, serializer<T>()) as T
    }

    /**
     * Non-inline version of [resolveFromCache]. Returns raw [Any?].
     * On web, cache always contains plaintext (PLAIN_TEXT mode internally).
     */
    @PublishedApi
    internal fun resolveFromCacheRaw(cache: Map<String, Any>, key: String, defaultValue: Any?, protection: KSafeProtection?, serializer: KSerializer<*>): Any? {
        val cacheKey = if (protection != null) "encrypted_$key" else key
        val cachedValue = cache[cacheKey] ?: return defaultValue

        return if (protection != null) {
            val jsonString = cachedValue as? String ?: return defaultValue
            if (jsonString == NULL_SENTINEL) return null
            try { jsonDecode(json, serializer, jsonString) } catch (_: Exception) { defaultValue }
        } else {
            if (isNullSentinel(cachedValue)) return null
            convertStoredValueRaw(cachedValue, defaultValue, serializer)
        }
    }

    @PublishedApi internal inline fun <reified T> convertStoredValue(storedValue: Any?, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return convertStoredValueRaw(storedValue, defaultValue, serializer<T>()) as T
    }

    /**
     * Non-inline version of [convertStoredValue]. On web all localStorage values are Strings.
     *
     * Dispatch uses the serializer's [kotlinx.serialization.descriptors.PrimitiveKind]
     * rather than the runtime type of [defaultValue] because Kotlin/JS collapses
     * numeric types (e.g. `0f is Int` returns `true` since JS stores `0f` as the
     * integer `0`). The serializer descriptor preserves the declared type.
     */
    @PublishedApi
    internal fun convertStoredValueRaw(storedValue: Any?, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (storedValue == null) return defaultValue
        if (isNullSentinel(storedValue)) return null

        val stringValue = storedValue as? String ?: return defaultValue

        return when (primitiveKindOrNull(serializer)) {
            kotlinx.serialization.descriptors.PrimitiveKind.BOOLEAN ->
                stringValue.toBooleanStrictOrNull() ?: defaultValue
            kotlinx.serialization.descriptors.PrimitiveKind.INT ->
                stringValue.toIntOrNull() ?: defaultValue
            kotlinx.serialization.descriptors.PrimitiveKind.LONG ->
                stringValue.toLongOrNull() ?: defaultValue
            kotlinx.serialization.descriptors.PrimitiveKind.FLOAT ->
                stringValue.toFloatOrNull() ?: defaultValue
            kotlinx.serialization.descriptors.PrimitiveKind.DOUBLE ->
                stringValue.toDoubleOrNull() ?: defaultValue
            kotlinx.serialization.descriptors.PrimitiveKind.STRING ->
                stringValue
            else -> {
                if (stringValue == NULL_SENTINEL) return null
                try { jsonDecode(json, serializer, stringValue) } catch (_: Exception) { defaultValue }
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

    actual inline fun <reified T> getDirect(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return getDirectRaw(key, defaultValue, serializer<T>()) as T
    }

    @PublishedApi
    internal actual fun getDirectRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        val detected = detectProtection(key)
        val cacheKey = if (detected != null) KeySafeMetadataManager.legacyEncryptedRawKey(key) else key
        val cachedValue = memoryCache[cacheKey]
        if (cachedValue != null) {
            return resolveFromCacheRaw(memoryCache, key, defaultValue, detected, serializer)
        }
        if (cacheInitialized) return defaultValue
        if (detected == null) {
            val storageKey = valueStorageKey(key)
            val value = localStorageGet(storageKey)
            if (value != null) {
                memoryCache[key] = value
                return convertStoredValueRaw(value, defaultValue, serializer)
            }
            val legacy = localStorageGet(legacyPlainStorageKey(key))
            if (legacy != null) {
                memoryCache[key] = legacy
                return convertStoredValueRaw(legacy, defaultValue, serializer)
            }
        }
        return defaultValue
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
        val rawKey = if (protection != null) KeySafeMetadataManager.legacyEncryptedRawKey(key) else key

        if (protection != null) {
            val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
            val alias = fileName?.let { "$it:$key" } ?: key

            updateMemoryCache(rawKey, jsonString)
            protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(KSafeProtection.DEFAULT)

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
                    is Boolean, is Int, is Long, is Float, is Double, is String -> value.toString()
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

            writeChannel.trySend(WriteOperation.Unencrypted(rawKey, key, storedValue))
        }
    }

    @PublishedApi
    internal fun encryptedPrefKey(key: String) = KeySafeMetadataManager.legacyEncryptedRawKey(key)

    @PublishedApi
    internal fun detectProtection(key: String): KSafeProtection? {
        val meta = protectionMap[key]
        KeySafeMetadataManager.parseProtection(meta)?.let { return it }
        // Fallback heuristic (legacy data without metadata)
        return if (memoryCache.containsKey(KeySafeMetadataManager.legacyEncryptedRawKey(key))) KSafeProtection.DEFAULT
        else null
    }

    @PublishedApi
    internal suspend fun putEncryptedRaw(
        key: String,
        value: Any?,
        requireUnlockedDevice: Boolean,
        serializer: KSerializer<*>
    ) {
        val alias = fileName?.let { "$it:$key" } ?: key
        val rawString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
        protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(KSafeProtection.DEFAULT)

        val plainBytes = rawString.encodeToByteArray()
        val encryptedBytes = doEncrypt(alias, plainBytes, requireUnlockedDevice)
        val encryptedString = encodeBase64Web(encryptedBytes)

        val storageKey = valueStorageKey(key)
        safeLocalStorageSet(storageKey, encryptedString)
        safeLocalStorageSet(
            metaStorageKey(key),
            protectionToMetaJson(
                protection = KSafeProtection.DEFAULT,
                requireUnlockedDevice = requireUnlockedDevice
            )
        )
        removeAllLegacyStorageKeys(key)

        updateMemoryCache(KeySafeMetadataManager.legacyEncryptedRawKey(key), rawString)
        yield()
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
        ensureCollectorStarted()

        val cachedValue = memoryCache[KeySafeMetadataManager.legacyEncryptedRawKey(key)]
        if (cachedValue != null) {
            return resolveFromCacheRaw(memoryCache, key, defaultValue, protection = KSafeProtection.DEFAULT, serializer)
        }

        if (cacheInitialized) return defaultValue

        val encryptedValue = localStorageGet(valueStorageKey(key))
            ?: localStorageGet(legacyEncryptedStorageKey(key))
            ?: return defaultValue

        try {
            val alias = fileName?.let { "$it:$key" } ?: key
            val encryptedBytes = decodeBase64Web(encryptedValue)
            val plainBytes = doDecrypt(alias, encryptedBytes)
            val rawString = plainBytes.decodeToString()

            updateMemoryCache(KeySafeMetadataManager.legacyEncryptedRawKey(key), rawString)

            if (rawString == NULL_SENTINEL) return null
            return jsonDecode(json, serializer, rawString)
        } catch (_: Exception) {
            return defaultValue
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
        ensureCollectorStarted()
        val detected = detectProtection(key)
        return if (detected != null) getEncryptedRaw(key, defaultValue, serializer) else getUnencryptedRaw(key, defaultValue, serializer)
    }

    @PublishedApi
    internal suspend fun getUnencryptedRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        ensureCollectorStarted()

        val cachedValue = memoryCache[key]
        if (cachedValue != null) {
            return resolveFromCacheRaw(memoryCache, key, defaultValue, protection = null, serializer)
        }

        if (cacheInitialized) return defaultValue

        val value = localStorageGet(valueStorageKey(key))
            ?: localStorageGet(legacyPlainStorageKey(key))
            ?: return defaultValue
        memoryCache[key] = value
        return convertStoredValueRaw(value, defaultValue, serializer)
    }

    @PublishedApi internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return getUnencryptedRaw(key, defaultValue, serializer<T>()) as T
    }

    @PublishedApi
    internal suspend fun putUnencryptedRaw(key: String, value: Any?, serializer: KSerializer<*>) {
        protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(null)
        safeLocalStorageSet(metaStorageKey(key), protectionToMetaJson(null))
        removeAllLegacyStorageKeys(key)
        if (value == null) {
            safeLocalStorageSet(valueStorageKey(key), NULL_SENTINEL)
            updateMemoryCache(key, NULL_SENTINEL)
            yield()
            return
        }

        val storedValue = when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> value.toString()
            else -> jsonEncode(json, serializer, value)
        }
        safeLocalStorageSet(valueStorageKey(key), storedValue)
        updateMemoryCache(key, storedValue)
        yield()
    }

    @PublishedApi internal suspend inline fun <reified T> putUnencrypted(key: String, value: T) {
        putUnencryptedRaw(key, value, serializer<T>())
    }

    actual inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> {
        @Suppress("UNCHECKED_CAST")
        return getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
    }

    @PublishedApi
    internal actual fun getFlowRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Flow<Any?> {
        return stateFlow.map { snapshot ->
            val protection = KeySafeMetadataManager.parseProtection(protectionMap[key])
                ?: if (snapshot.containsKey(KeySafeMetadataManager.legacyEncryptedRawKey(key))) KSafeProtection.DEFAULT
                else null
            when (protection) {
                null -> {
                    val value = snapshot[key]
                    if (value != null) convertStoredValueRaw(value, defaultValue, serializer) else defaultValue
                }
                else -> {
                    val encValue = snapshot[KeySafeMetadataManager.legacyEncryptedRawKey(key)]
                    if (encValue != null) {
                        val jsonString = encValue as? String ?: return@map defaultValue
                        if (jsonString == NULL_SENTINEL) null
                        else {
                            try { jsonDecode(json, serializer, jsonString) } catch (_: Exception) { defaultValue }
                        }
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
        localStorageRemove(valueStorageKey(key))
        localStorageRemove(metaStorageKey(key))
        removeAllLegacyStorageKeys(key)

        val alias = fileName?.let { "$it:$key" } ?: key
        doDeleteKey(alias)

        updateMemoryCache(key, null)
        updateMemoryCache(KeySafeMetadataManager.legacyEncryptedRawKey(key), null)
        protectionMap.remove(key)
    }

    actual fun deleteDirect(key: String) {
        updateMemoryCache(key, null)
        updateMemoryCache(KeySafeMetadataManager.legacyEncryptedRawKey(key), null)
        protectionMap.remove(key)

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
        protectionMap.clear()
        emitStateFlow()
    }

    // --- PER-KEY STORAGE QUERY ---

    actual fun getKeyInfo(key: String): KSafeKeyInfo? {
        if (!memoryCache.containsKey(KeySafeMetadataManager.legacyEncryptedRawKey(key)) && !memoryCache.containsKey(key)) return null

        val protection = KeySafeMetadataManager.parseProtection(protectionMap[key])
            ?: if (memoryCache.containsKey(KeySafeMetadataManager.legacyEncryptedRawKey(key))) {
                KSafeProtection.DEFAULT
            } else {
                null
            }
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

    // --- BIOMETRIC API ---

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
