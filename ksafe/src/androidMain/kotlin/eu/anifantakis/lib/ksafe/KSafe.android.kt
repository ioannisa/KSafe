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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
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
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default
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
        testEngine: KSafeEncryption
    ) : this(context, fileName, lazyLoad, memoryPolicy, config, securityPolicy) {
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

    // Create a DataStore for our preferences.
    @PublishedApi
    internal val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
        produceFile = {
            val file =
                fileName?.let { "eu_anifantakis_ksafe_datastore_${fileName}" } ?: "eu_anifantakis_ksafe_datastore"
            context.preferencesDataStoreFile(file)
        }
    )

    /**
     * **Atomic In-Memory Cache (Hot State).**
     *
     * Holds a map of pre-decrypted values: `Map<Key, Value>`.
     * This enables [getDirect] to return immediately without blocking for disk I/O.
     */
    @PublishedApi
    internal val memoryCache = AtomicReference<Map<String, Any>?>(null)

    /**
     * **Dirty Keys Tracker.**
     *
     * An atomic set of keys currently being written to disk.
     * This prevents the background DataStore observer from overwriting our optimistic
     * in-memory updates with stale data from disk during the write window.
     * Uses AtomicReference with CAS operations for lock-free thread safety.
     */
    @PublishedApi
    internal val dirtyKeys = AtomicReference<Set<String>>(emptySet())

    /**
     * Map of scope -> timestamp for biometric authorization sessions.
     * Each scope maintains its own authorization timestamp.
     */
    @PublishedApi
    internal val biometricAuthSessions = AtomicReference<Map<String, Long>>(emptyMap())

    /**
     * Atomically adds a key to the dirty set using CAS loop.
     */
    @PublishedApi
    internal fun addDirtyKey(key: String) {
        while (true) {
            val current = dirtyKeys.get()
            val next = current + key
            if (dirtyKeys.compareAndSet(current, next)) break
        }
    }

    /**
     * Atomically removes a key from the dirty set using CAS loop.
     */
    @PublishedApi
    internal fun removeDirtyKey(key: String) {
        while (true) {
            val current = dirtyKeys.get()
            val next = current - key
            if (dirtyKeys.compareAndSet(current, next)) break
        }
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
     * Updates the atomic [memoryCache] based on the raw [Preferences] from DataStore.
     *
     * **Lock-Free Design:**
     * This function is lock-free to prevent deadlocks and race conditions with [updateMemoryCache].
     * The dirty keys mechanism ensures that optimistic writes from [putDirect] are not
     * overwritten by stale data from DataStore during the write window.
     */
    @PublishedApi
    internal fun updateCache(prefs: Preferences) {
        val currentCache = memoryCache.get() ?: emptyMap()
        val newCache = mutableMapOf<String, Any>()
        val prefsMap = prefs.asMap()
        val encryptedPrefix = "encrypted_"
        val currentDirty = dirtyKeys.get() // Snapshot of dirty keys

        for ((key, value) in prefsMap) {
            val keyName = key.name

            // Dirty Check: If a local write is pending for this key,
            // prioritize the local optimistic value over the (potentially stale) disk value.
            if (currentDirty.contains(keyName)) {
                currentCache[keyName]?.let { newCache[keyName] = it }
                continue
            }

            // Handle Encrypted Entries
            if (keyName.startsWith(encryptedPrefix)) {
                // ENCRYPTED ENTRY
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
                    // SECURITY MODE: Do NOT decrypt. Store the raw ciphertext string in RAM.
                    // We will decrypt it only when the user asks for it in resolveFromCache.
                    newCache[keyName] = value
                } else {
                    // PERFORMANCE MODE: Decrypt now, store plaintext in RAM.
                    val originalKey = keyName.removePrefix(encryptedPrefix)
                    val encryptedString = value as? String
                    if (encryptedString != null) {
                        try {
                            val ciphertext = decodeBase64(encryptedString)
                            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, originalKey).joinToString(".")
                            val decryptedBytes = engine.decrypt(keyAlias, ciphertext)
                            newCache[keyName] = decryptedBytes.decodeToString()
                        } catch (_: Exception) { }
                    }
                }
            }
            // Handle Unencrypted Entries
            else if (!keyName.startsWith("ksafe_")) {
                newCache[keyName] = value
            }
        }

        // CRITICAL: Use CAS loop for the final update to handle concurrent putDirect operations.
        // This ensures we don't lose values that were added via updateMemoryCache during our processing.
        while (true) {
            val latestCache = memoryCache.get()  // Keep the actual reference (could be null)
            val latestCacheOrEmpty = latestCache ?: emptyMap()
            val finalDirty = dirtyKeys.get()
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

    /**
     * Thread-safe helper to update specific keys in the memory cache.
     * Uses a CAS (Compare-And-Swap) loop to ensure atomicity.
     */
    @PublishedApi
    internal fun updateMemoryCache(rawKeyName: String, value: Any?) {
        while (true) {
            val current = memoryCache.get() ?: emptyMap()
            val newMap = current.toMutableMap()

            // Update or remove based on value presence
            if (value == null) newMap.remove(rawKeyName) else newMap[rawKeyName] = value

            // Attempt to atomically swap the old map with the new one.
            if (memoryCache.compareAndSet(current, newMap)) break
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
            // Encrypted values are stored as JSON strings in the cache (decrypted from bytes)
            var jsonString: String?

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
                // SECURITY MODE: Decrypt On-Demand
                try {
                    val encryptedString = cachedValue as? String ?: return defaultValue
                    val ciphertext = decodeBase64(encryptedString)
                    val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
                    val decryptedBytes = engine.decrypt(keyAlias, ciphertext)
                    jsonString = decryptedBytes.decodeToString()
                } catch (_: Exception) {
                    // FALLBACK: If decryption fails, check if this is an Optimistic Update (Plain JSON)
                    // putDirect() writes JSON temporarily to allow instant read-back before encryption.
                    jsonString = cachedValue as? String
                }
            } else {
                // PERFORMANCE MODE: Already decrypted
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

    // ----- Public API implementation -----

    actual inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean): T {
        val currentCache = memoryCache.get()

        // 1. FAST PATH: Cache is ready (Background preload finished) -> Return instantly
        if (currentCache != null) {
            return resolveFromCache(currentCache, key, defaultValue, encrypted)
        }

        // 2. FALLBACK PATH: Cache not ready -> Block to fetch immediately (Cold Start)
        // This only happens if accessed before the background loader finishes.
        return runBlocking {
            // Double-check optimization
            memoryCache.get()?.let { return@runBlocking resolveFromCache(it, key, defaultValue, encrypted) }

            val prefs = dataStore.data.first()
            updateCache(prefs) // Synchronized
            val populatedCache = memoryCache.get() ?: emptyMap()
            resolveFromCache(populatedCache, key, defaultValue, encrypted)
        }
    }

    actual inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean) {
        val rawKey = if (encrypted) "encrypted_$key" else key

        // 1. Mark key as dirty to prevent overwrite by background observer
        addDirtyKey(rawKey)

        // 2. Optimistic Update (Immediate memory update)
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

        // 3. Async Disk Write (Fire and forget)
        CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
            try {
                put(key, value, encrypted)
            } finally {
                // Clear dirty flag only after write completes (or fails)
                removeDirtyKey(rawKey)
            }
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

        // Use encryption engine
        val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
        val ciphertext = engine.encrypt(keyAlias, jsonString.encodeToByteArray())

        storeEncryptedData(key, ciphertext)

        // Sync cache

        // Optimistic Update:
        // If ENCRYPTED policy, store Ciphertext (Base64). If PLAIN, store JSON.
        val cacheValue = if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
            encodeBase64(ciphertext)
        } else {
            jsonString
        }
        updateMemoryCache("encrypted_$key", cacheValue)
    }

    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        // Check cache first
        val currentCache = memoryCache.get()
        if (currentCache != null) return resolveFromCache(currentCache, key, defaultValue, encrypted = true)

        // Fallback to disk (ensure cache is populated)
        val prefs = dataStore.data.first()
        updateCache(prefs)
        val populatedCache = memoryCache.get() ?: emptyMap()
        return resolveFromCache(populatedCache, key, defaultValue, encrypted = true)
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
        val currentCache = memoryCache.get()
        if (currentCache != null) return resolveFromCache(currentCache, key, defaultValue, encrypted = false)

        // Fallback to disk
        val prefs = dataStore.data.first()
        updateCache(prefs)
        val populatedCache = memoryCache.get() ?: emptyMap()
        return resolveFromCache(populatedCache, key, defaultValue, encrypted = false)
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
    }

    /**
     * Deletes a value from DataStore without using coroutines.
     * This function is **non-blocking**.
     *
     * @param key The key of the value to delete.
     */
    actual fun deleteDirect(key: String) {
        // Optimistic update
        updateMemoryCache(key, null)
        updateMemoryCache("encrypted_$key", null)

        CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
            delete(key)
        }
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
        memoryCache.set(emptyMap())
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