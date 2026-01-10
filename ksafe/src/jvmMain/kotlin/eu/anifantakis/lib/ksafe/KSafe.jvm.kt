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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.ConcurrentHashMap
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

    // Use AtomicReference and ConcurrentHashMap for thread safety (matches your working code)
    @PublishedApi internal val memoryCache = AtomicReference<Map<String, Any>?>(null)
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

    @PublishedApi
    internal fun updateMemoryCache(key: String, value: Any?) {
        while (true) {
            val current = memoryCache.get() ?: emptyMap()
            val newMap = current.toMutableMap()
            if (value == null) newMap.remove(key) else newMap[key] = value
            if (memoryCache.compareAndSet(current, newMap)) break
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
     * Updates the atomic [memoryCache] based on the raw [Preferences] from DataStore.
     *
     * **Lock-Free Design:**
     * This function is lock-free to prevent race conditions with [updateMemoryCache].
     * The dirty keys mechanism ensures that optimistic writes from [putDirect] are not
     * overwritten by stale data from DataStore during the write window.
     */
    @PublishedApi
    internal fun updateCache(prefs: Preferences) {
        val currentCache = memoryCache.get() ?: emptyMap()
        val newCache = mutableMapOf<String, Any>()
        val prefsMap = prefs.asMap()
        val encryptedPrefix = "encrypted_"
        val currentDirty = dirtyKeys.toSet() // Snapshot of dirty keys

        for ((key, value) in prefsMap) {
            val keyName = key.name
            // Dirty Check: preserve optimistic updates from putDirect
            if (currentDirty.contains(keyName)) {
                currentCache[keyName]?.let { newCache[keyName] = it }
                continue
            }
            if (keyName.startsWith(encryptedPrefix)) {
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
                    // POLICY: ENCRYPTED -> Store raw ciphertext (value is already String/Base64)
                    newCache[keyName] = value
                } else {
                    // POLICY: PLAIN_TEXT -> Decrypt immediately
                    val originalKey = keyName.removePrefix(encryptedPrefix)
                    val encryptedString = value as? String
                    if (encryptedString != null) {
                        try {
                            val alias = fileName?.let { "$it:$originalKey" } ?: originalKey
                            val encryptedBytes = decodeBase64(encryptedString)
                            val plainBytes = engine.decrypt(alias, encryptedBytes)
                            newCache[keyName] = plainBytes.toString(Charsets.UTF_8)
                        } catch (_: Exception) { /* Ignore failures */ }
                    }
                }
            } else if (!keyName.startsWith("ksafe_")) {
                newCache[keyName] = value
            }
        }

        // CRITICAL: Use CAS loop for the final update to handle concurrent putDirect operations.
        // This ensures we don't lose values that were added via updateMemoryCache during our processing.
        while (true) {
            val latestCache = memoryCache.get()  // Keep the actual reference (could be null)
            val latestCacheOrEmpty = latestCache ?: emptyMap()
            val finalDirty = dirtyKeys.toSet()
            val finalCache = newCache.toMutableMap()

            // Preserve ALL dirty keys from the latest cache
            for (dirtyKey in finalDirty) {
                if (!finalCache.containsKey(dirtyKey)) {
                    latestCacheOrEmpty[dirtyKey]?.let { finalCache[dirtyKey] = it }
                }
            }

            // Try to atomically update. Compare against actual reference (latestCache, not latestCacheOrEmpty).
            if (memoryCache.compareAndSet(latestCache, finalCache)) break
        }
    }

    @PublishedApi internal inline fun <reified T> resolveFromCache(cache: Map<String, Any>, key: String, defaultValue: T, encrypted: Boolean): T {
        val cacheKey = if (encrypted) "encrypted_$key" else key
        val cachedValue = cache[cacheKey] ?: return defaultValue

        return if (encrypted) {
            var jsonString: String?

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
                // POLICY: ENCRYPTED -> Decrypt On-Demand
                try {
                    val encryptedString = cachedValue as? String ?: return defaultValue
                    val ciphertext = decodeBase64(encryptedString)

                    // Decrypt using the engine
                    val alias = fileName?.let { "$it:$key" } ?: key
                    val plainBytes = engine.decrypt(alias, ciphertext)

                    jsonString = plainBytes.toString(Charsets.UTF_8)
                } catch (_: Exception) {
                    // FALLBACK: Optimistic Update (putDirect stores Plain JSON initially)
                    // If decryption fails (e.g. invalid Base64 or AES error), assume it's JSON.
                    jsonString = cachedValue as? String
                }
            } else {
                // POLICY: PLAIN_TEXT -> Already decrypted
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
        val currentCache = memoryCache.get()
        // 1. FAST PATH (Hot Cache)
        if (currentCache != null) return resolveFromCache(currentCache, key, defaultValue, encrypted)

        // 2. FALLBACK PATH (Cold Cache)
        // Matches Hybrid logic: Block main thread once to load cache if accessed too early.
        return runBlocking {
            val prefs = dataStore.data.first()
            updateCache(prefs)
            val populatedCache = memoryCache.get() ?: emptyMap()
            resolveFromCache(populatedCache, key, defaultValue, encrypted)
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

        // Async Write
        CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
            try { put(key, value, encrypted) } finally { dirtyKeys.remove(rawKey) }
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
        val currentCache = memoryCache.get()
        if (currentCache != null) return resolveFromCache(currentCache, key, defaultValue, encrypted = true)
        val prefs = dataStore.data.first()
        updateCache(prefs)
        val populatedCache = memoryCache.get() ?: emptyMap()
        return resolveFromCache(populatedCache, key, defaultValue, encrypted = true)
    }

    actual suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean): T {
        return if (encrypted) getEncrypted(key, defaultValue) else getUnencrypted(key, defaultValue)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        val currentCache = memoryCache.get()
        if (currentCache != null) return resolveFromCache(currentCache, key, defaultValue, encrypted = false)
        val prefs = dataStore.data.first()
        updateCache(prefs)
        val populatedCache = memoryCache.get() ?: emptyMap()
        return resolveFromCache(populatedCache, key, defaultValue, encrypted = false)
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
        if (encrypted) putEncrypted(key, value) else putUnencrypted(key, value)
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
        updateMemoryCache(key, null)
        updateMemoryCache("encrypted_$key", null)
        CoroutineScope(Dispatchers.IO + SupervisorJob()).launch { delete(key) }
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
        memoryCache.set(emptyMap())
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