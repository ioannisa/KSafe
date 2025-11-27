package eu.anifantakis.lib.ksafe

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
import java.security.KeyStore
import java.util.Collections
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
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
 */
actual class KSafe(
    private val context: Context,
    @PublishedApi internal val fileName: String? = null,
    private val lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED
) {
    companion object Companion {
        // we intentionally don't allow "." to avoid path traversal vulnerabilities
        private val fileNameRegex = Regex("[a-z]+")
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS_PREFIX = "eu.anifantakis.ksafe"
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
    }

    /**
     * Lock object to synchronize cache updates between background preloader and main thread fallback.
     */
    private val cacheLock = Any()

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
     * A thread-safe set of keys currently being written to disk.
     * This prevents the background DataStore observer from overwriting our optimistic
     * in-memory updates with stale data from disk during the write window.
     */
    @PublishedApi internal val dirtyKeys: MutableSet<String> = Collections.synchronizedSet(HashSet())

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
     * Synchronized to prevent race conditions between Background Preload and Main Thread Fallback.
     */
    @PublishedApi
    internal fun updateCache(prefs: Preferences) {
        synchronized(cacheLock) {
            val currentCache = memoryCache.get() ?: emptyMap()
            val newCache = mutableMapOf<String, Any>()
            val prefsMap = prefs.asMap()
            val encryptedPrefix = "encrypted_"

            for ((key, value) in prefsMap) {
                val keyName = key.name

                // Dirty Check: If a local write is pending for this key,
                // prioritize the local optimistic value over the (potentially stale) disk value.
                if (dirtyKeys.contains(keyName)) {
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
                                val decryptedBytes = decryptWithKeystore(keyAlias, ciphertext)
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

            // Important: Preserve any dirty keys that haven't been persisted to disk yet.
            synchronized(dirtyKeys) {
                for (dirtyKey in dirtyKeys) {
                    if (!newCache.containsKey(dirtyKey)) {
                        currentCache[dirtyKey]?.let { newCache[dirtyKey] = it }
                    }
                }
            }

            // Atomically replace the entire cache with the freshly computed map.
            memoryCache.set(newCache)
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
                    val decryptedBytes = decryptWithKeystore(keyAlias, ciphertext)
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

        // 1. Lock key to prevent overwrite by background observer
        dirtyKeys.add(rawKey)

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
                dirtyKeys.remove(rawKey)
            }
        }
    }

    // ----- Android Keystore Encryption Helpers -----
    @PublishedApi
    internal fun encryptedPrefKey(key: String) = stringPreferencesKey("encrypted_$key")

    /**
     * Gets or creates a secret key in Android Keystore
     */
    private fun getOrCreateSecretKey(keyAlias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }

        // Check if key already exists
        if (keyStore.containsAlias(keyAlias)) {
            return keyStore.getKey(keyAlias, null) as SecretKey
        }

        // Generate new key
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    /**
     * Encrypts data using Android Keystore
     */
    fun encryptWithKeystore(keyAlias: String, plaintext: ByteArray): ByteArray {
        val secretKey = getOrCreateSecretKey(keyAlias)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)

        // Combine IV and ciphertext
        return iv + ciphertext
    }

    /**
     * Decrypts data using Android Keystore
     */
    fun decryptWithKeystore(keyAlias: String, encryptedData: ByteArray): ByteArray {
        val secretKey = getOrCreateSecretKey(keyAlias)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        // Extract IV and ciphertext
        val iv = encryptedData.sliceArray(0..11)
        val ciphertext = encryptedData.sliceArray(12 until encryptedData.size)

        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return cipher.doFinal(ciphertext)
    }

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

        // Use Android Keystore for encryption
        val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
        val ciphertext = encryptWithKeystore(keyAlias, jsonString.encodeToByteArray())

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
                        val decryptedBytes = decryptWithKeystore(keyAlias, ciphertext)
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

        // Also try to delete the corresponding encryption key from Keystore
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                load(null)
            }
            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }
        } catch (_: Exception) {
            // Ignore errors when deleting from keystore
        }

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

        // Delete all associated Keystore entries
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }

        encryptedKeys.forEach { keyId ->
            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, keyId).joinToString(".")
            try {
                if (keyStore.containsAlias(keyAlias)) {
                    keyStore.deleteEntry(keyAlias)
                }
            } catch (_: Exception) {
                // Ignore errors when deleting from keystore
            }
        }

        // Clear cache
        memoryCache.set(emptyMap())
    }
}