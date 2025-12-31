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
private fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

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
 */
actual class KSafe(
    @PublishedApi internal val fileName: String? = null,
    private val lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    private val config: KSafeConfig = KSafeConfig()
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
        testEngine: KSafeEncryption
    ) : this(fileName, lazyLoad, memoryPolicy, config) {
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
            serviceName = SERVICE_NAME,
            keyPrefix = KEY_PREFIX
        )
    }

    init {
        if (fileName != null) {
            if (!fileName.matches(fileNameRegex)) {
                throw IllegalArgumentException("File name must contain only lowercase letters.")
            }
        }
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

    @PublishedApi internal val memoryCache = AtomicReference<Map<String, Any>?>(null)
    private val dirtyKeys = AtomicReference<Set<String>>(emptySet())
    @PublishedApi internal val json = Json { ignoreUnknownKeys = true }

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
        // Use mock keychain in simulator
        if (MockKeychain.isSimulator()) {
            val basePrefix = listOfNotNull(KEY_PREFIX, fileName).joinToString(".")
            val prefixWithDelimiter = "$basePrefix."

            MockKeychain.getAllKeys().forEach { account ->
                if (account.startsWith(prefixWithDelimiter)) {
                    val keyId = account.removePrefix(prefixWithDelimiter)

                    // FIX: Don't delete keys belonging to other KSafe instances
                    if (fileName == null && keyId.contains('.')) return@forEach

                    if (keyId !in validKeys) {
                        MockKeychain.delete(account)
                    }
                }
            }
            return
        }

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

    @PublishedApi
    internal fun updateMemoryCache(key: String, value: Any?) {
        while (true) {
            val current = memoryCache.value ?: emptyMap()
            val newMap = current.toMutableMap()
            if (value == null) newMap.remove(key) else newMap[key] = value
            if (memoryCache.compareAndSet(current, newMap)) break
        }
    }

    /**
     * Updates the atomic [memoryCache] based on the raw [Preferences] from DataStore.
     *
     * **Lock-Free Design:**
     * This function is lock-free to prevent race conditions with [updateMemoryCache].
     * The dirty keys mechanism ensures that optimistic writes from [putDirect] are not
     * overwritten by stale data from DataStore during the write window.
     *
     * Cleanup is handled separately via [ensureCleanupPerformed] which has its own mutex.
     */
    @PublishedApi
    internal suspend fun updateCache(prefs: Preferences) {
        // Ensure cleanup runs once (has its own mutex protection)
        ensureCleanupPerformed()

        // Lock-free cache update using dirty keys for coordination
        val currentCache = memoryCache.value ?: emptyMap()
        val newCache = mutableMapOf<String, Any>()
        val prefsMap = prefs.asMap()
        val encryptedPrefix = fileName?.let { "${fileName}_" } ?: "encrypted_"
        val currentDirty = dirtyKeys.value // Snapshot of dirty keys

        for ((key, value) in prefsMap) {
            val keyName = key.name
            // Dirty Check: preserve optimistic updates from putDirect
            if (currentDirty.contains(keyName)) {
                currentCache[keyName]?.let { newCache[keyName] = it }
                continue
            }

            if (keyName.startsWith(encryptedPrefix)) {
                // ENCRYPTED ENTRY
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
                        } catch (_: Exception) { /* Ignore failures */ }
                    }
                }
            } else if (!keyName.startsWith("ksafe_")) {
                // UNENCRYPTED ENTRY
                newCache[keyName] = value
            }
        }

        // CRITICAL: Use CAS loop for the final update to handle concurrent putDirect operations.
        // This ensures we don't lose values that were added via updateMemoryCache during our processing.
        while (true) {
            val latestCache = memoryCache.value  // Keep the actual reference (could be null)
            val latestCacheOrEmpty = latestCache ?: emptyMap()
            val finalDirty = dirtyKeys.value
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

    @PublishedApi
    internal fun addDirtyKey(key: String) {
        while (true) {
            val current = dirtyKeys.value
            val next = current + key
            if (dirtyKeys.compareAndSet(current, next)) break
        }
    }

    @PublishedApi
    internal fun removeDirtyKey(key: String) {
        while (true) {
            val current = dirtyKeys.value
            val next = current - key
            if (dirtyKeys.compareAndSet(current, next)) break
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
            var jsonString: String?

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED) {
                // SECURITY MODE: Decrypt On-Demand
                try {
                    val encryptedString = cachedValue as? String ?: return defaultValue
                    val ciphertext = decodeBase64(encryptedString)

                    // Decrypt using the engine
                    val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
                    val decryptedBytes = engine.decrypt(keyId, ciphertext)
                    jsonString = decryptedBytes.decodeToString()
                } catch (_: Exception) {
                    // FALLBACK: If decryption fails, check if this is an Optimistic Update (Plain JSON)
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
        val currentCache = memoryCache.value
        if (currentCache != null) return resolveFromCache(currentCache, key, defaultValue, encrypted = false)

        ensureCleanupPerformed() // Thread-safe cleanup

        val prefs = dataStore.data.first()
        updateCache(prefs) // Waits for Mutex
        val populatedCache = memoryCache.value ?: emptyMap()
        return resolveFromCache(populatedCache, key, defaultValue, encrypted = false)
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

        // Use mock keychain in simulator
        if (MockKeychain.isSimulator()) {
            MockKeychain.delete(account)
            return
        }

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

        val rawKey = fileName?.let { "${fileName}_$key" } ?: "encrypted_$key"
        updateMemoryCache(rawKey, jsonString)
    }

    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        val currentCache = memoryCache.value
        if (currentCache != null) return resolveFromCache(currentCache, key, defaultValue, encrypted = true)

        ensureCleanupPerformed()

        val prefs = dataStore.data.first()
        updateCache(prefs) // Waits for Mutex
        val populatedCache = memoryCache.value ?: emptyMap()
        return resolveFromCache(populatedCache, key, defaultValue, encrypted = true)
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
        val currentCache = memoryCache.value

        // 2. FAST PATH (Cache Ready)
        // If background preload finished, return instantly.
        if (currentCache != null) {
            return resolveFromCache(currentCache, key, defaultValue, encrypted)
        }

        // 3. FALLBACK PATH (Cache Not Ready)
        // "Abandon" waiting for the background job and fetch/build it ourselves immediately.
        // This blocks the thread ONLY for the first call.
        return runBlocking {
            // Optimization: Check if background thread finished while we were entering runBlocking
            memoryCache.value?.let { return@runBlocking resolveFromCache(it, key, defaultValue, encrypted) }

            val prefs = dataStore.data.first()
            updateCache(prefs) // Waits for Mutex to ensure safety
            val populatedCache = memoryCache.value ?: emptyMap()
            resolveFromCache(populatedCache, key, defaultValue, encrypted)
        }
    }

    @Suppress("UNCHECKED_CAST")
    @OptIn(ExperimentalCoroutinesApi::class)
    @PublishedApi
    internal inline fun <reified T> getUnencryptedFlow(key: String, defaultValue: T): Flow<T> {
        // Ensure cleanup on first access
        CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
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

        CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
            try { put(key, value, encrypted) } finally { removeDirtyKey(rawKey) }
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
        val encKeyName = fileName?.let { "${fileName}_$key" } ?: "encrypted_$key"
        updateMemoryCache(key, null)
        updateMemoryCache(encKeyName, null)
        CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
            delete(key)
        }
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

        // Clear mock keychain if in simulator
        if (MockKeychain.isSimulator()) {
            MockKeychain.clear()
        }
        memoryCache.value = emptyMap()
    }
}

// iOS: non-inline helper to get the AES-GCM algorithm instance.
fun obtainAesGcm(): AES.GCM {
    return CryptographyProvider.CryptoKit.get(AES.GCM)
}