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
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.providers.cryptokit.CryptoKit
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
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
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.KSerializer
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
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecClassKey
import platform.Security.kSecReturnAttributes
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.concurrent.AtomicReference
import kotlin.time.ComparableTimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

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
 * @property useSecureEnclave **Deprecated.** Prefer per-property [KSafeProtection.HARDWARE_ISOLATED].
 *   When true, [KSafeProtection.DEFAULT] is automatically promoted to [KSafeProtection.HARDWARE_ISOLATED].
 *   Existing keys are unaffected — they remain in whatever storage they were originally created in.
 */
actual class KSafe(
    @PublishedApi internal val fileName: String? = null,
    private val lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    private val config: KSafeConfig = KSafeConfig(),
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    @PublishedApi internal val plaintextCacheTtl: Duration = 5.seconds,
    @Deprecated("Use KSafeProtection.HARDWARE_ISOLATED per-property instead")
    private val useSecureEnclave: Boolean = false
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
        plaintextCacheTtl: Duration = 5.seconds,
        useSecureEnclave: Boolean = false,
        testEngine: KSafeEncryption
    ) : this(fileName, lazyLoad, memoryPolicy, config, securityPolicy, plaintextCacheTtl, useSecureEnclave) {
        _testEngine = testEngine
    }

    // Internal injection hook for testing
    @PublishedApi
    internal var _testEngine: KSafeEncryption? = null

    companion object Companion {
        // Must start with a lowercase letter; may also contain digits and underscores.
        // We intentionally forbid ".", "/" and uppercase to prevent path-traversal and
        // platform-specific case-sensitivity issues.
        private val fileNameRegex = Regex("[a-z][a-z0-9_]*")
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

    private val hasSecureEnclave: Boolean = !isSimulator()

    actual val deviceKeyStorages: Set<KSafeKeyStorage> = buildSet {
        add(KSafeKeyStorage.HARDWARE_BACKED)
        if (hasSecureEnclave) add(KSafeKeyStorage.HARDWARE_ISOLATED)
    }

    @Suppress("DEPRECATION")
    @PublishedApi
    internal fun resolveProtection(protection: KSafeProtection?): KSafeProtection? =
        if (protection == KSafeProtection.DEFAULT && useSecureEnclave) KSafeProtection.HARDWARE_ISOLATED
        else protection

    init {
        if (fileName != null) {
            if (!fileName.matches(fileNameRegex)) {
                throw IllegalArgumentException("File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores.")
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
     * Per-key protection metadata cache.
     * Maps user key to protection level string ("DEFAULT" or "HARDWARE_ISOLATED").
     * Populated from `__ksafe_prot_{key}__` entries in DataStore.
     */
    @PublishedApi
    internal val protectionMap = AtomicReference<Map<String, String>>(emptyMap())

    /**
     * **Short-lived plaintext cache for [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE].**
     */
    @PublishedApi
    internal class CachedPlaintext(val value: String, val expiresAt: ComparableTimeMark)

    @PublishedApi
    internal val plaintextCache = AtomicReference<Map<String, CachedPlaintext>>(emptyMap())

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
    @PublishedApi internal val json: Json = config.json

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
            val keyId: String,
            val hardwareIsolated: Boolean = false,
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

        // Collect keys that need Keychain deletion
        val keysToDeleteFromKeychain = mutableListOf<String>()

        // Pre-encrypt all encrypted operations (done in background, not UI thread)
        val encryptedData = mutableMapOf<String, ByteArray>()
        for (op in batch) {
            if (op is WriteOperation.Encrypted) {
                val ciphertext = engine.encrypt(
                    identifier = op.keyId,
                    data = op.jsonString.encodeToByteArray(),
                    hardwareIsolated = op.hardwareIsolated,
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
                        prefs.removeAllLegacyKeys(op.key)
                    }
                    is WriteOperation.Encrypted -> {
                        val ciphertext = encryptedData[op.key]!!
                        prefs[valuePrefKey(op.key)] = encodeBase64(ciphertext)
                        prefs[metaPrefKey(op.key)] = protectionToMetaJson(
                            protection = if (op.hardwareIsolated) KSafeProtection.HARDWARE_ISOLATED else KSafeProtection.DEFAULT,
                            requireUnlockedDevice = op.requireUnlockedDevice
                        )
                        prefs.removeAllLegacyKeys(op.key)
                    }
                    is WriteOperation.Delete -> {
                        prefs.removeByKeyName(valueRawKey(op.key))
                        prefs.remove(metaPrefKey(op.key))
                        prefs.removeAllLegacyKeys(op.key)
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

        // Restore ENCRYPTED semantics: replace plaintext with ciphertext in cache.
        // Uses CAS to avoid overwriting newer putDirect values.
        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED
            || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE
        ) {
            for (op in batch) {
                if (op is WriteOperation.Encrypted) {
                    val ciphertext = encryptedData[op.key]!!
                    val base64Ciphertext = encodeBase64(ciphertext)
                    while (true) {
                        val current = memoryCache.value
                        if (current[op.rawKey] != op.jsonString) break  // newer write, skip
                        val updated = current.toMutableMap()
                        updated[op.rawKey] = base64Ciphertext
                        if (memoryCache.compareAndSet(current, updated)) break
                    }
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
            migrateAccessPolicyIfNeeded()
            cleanupOrphanedCiphertext()
            dataStore.data.collect { updateCache(it) }
        }
    }

    /**
     * Detects and removes orphaned ciphertext entries from DataStore.
     *
     * After device reset or Keychain clearing, encrypted entries become permanently
     * undecryptable. This method probes each encrypted entry and removes those whose
     * keys are gone.
     *
     * Entries that fail with "device is locked" or "Keychain" errors are skipped
     * (temporary failure, retry next launch).
     */
    private suspend fun cleanupOrphanedCiphertext() {
        val prefs = dataStore.data.first()
        val orphanedKeys = mutableListOf<String>()
        val protectionByKey = mutableMapOf<String, KSafeProtection>()
        val legacyEncryptedPrefix = fileName?.let { "${fileName}_" } ?: "encrypted_"

        for ((prefKey, prefValue) in prefs.asMap()) {
            val keyName = prefKey.name
            when {
                keyName.startsWith(KeySafeMetadataManager.META_PREFIX) && keyName.endsWith(KeySafeMetadataManager.META_SUFFIX) -> {
                    val userKey = keyName
                        .removePrefix(KeySafeMetadataManager.META_PREFIX)
                        .removeSuffix(KeySafeMetadataManager.META_SUFFIX)
                    KeySafeMetadataManager.parseProtection(prefValue as? String)?.let { protectionByKey[userKey] = it }
                }
                KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) != null -> {
                    val userKey = KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) ?: continue
                    if (!protectionByKey.containsKey(userKey)) {
                        KeySafeMetadataManager.parseProtection(prefValue as? String)?.let { protectionByKey[userKey] = it }
                    }
                }
            }
        }

        for ((prefKey, prefValue) in prefs.asMap()) {
            val keyName = prefKey.name
            // Preserve legacy encrypted entries to avoid destructive cleanup on upgrades.
            if (keyName.startsWith(legacyEncryptedPrefix)) continue
            if (!keyName.startsWith(KeySafeMetadataManager.VALUE_PREFIX)) continue
            val originalKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)

            val protection = protectionByKey[originalKey]
            if (protection == null) continue

            val encryptedString = prefValue as? String ?: continue
            val keyId = listOfNotNull(KEY_PREFIX, fileName, originalKey).joinToString(".")

            try {
                val ciphertext = decodeBase64(encryptedString)
                engine.decrypt(keyId, ciphertext)
            } catch (e: Exception) {
                val msg = e.message ?: ""
                if (msg.contains("device is locked", ignoreCase = true) ||
                    msg.contains("Keychain", ignoreCase = true)) {
                    continue
                }
                if (msg.contains("No encryption key found", ignoreCase = true) ||
                    msg.contains("key not found", ignoreCase = true)) {
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
            while (true) {
                val current = memoryCache.value
                val updated = current.toMutableMap()
                orphanedKeys.forEach { keyName ->
                    val originalKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                    updated.remove(originalKey)
                    updated.remove(legacyEncryptedRawKey(originalKey))
                }
                if (memoryCache.compareAndSet(current, updated)) break
            }
        }
    }

    /** Access policy is now set per write mode; no global migration is required. */
    private suspend fun migrateAccessPolicyIfNeeded() = Unit

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
    internal fun legacyEncryptedPrefKey(key: String) = stringPreferencesKey(
        fileName?.let { "${fileName}_$key" } ?: KeySafeMetadataManager.legacyEncryptedRawKey(key)
    )

    @PublishedApi
    internal fun legacyProtectionMetaKey(key: String) =
        stringPreferencesKey(KeySafeMetadataManager.legacyProtectionRawKey(key))

    @PublishedApi
    internal fun legacyEncryptedRawKey(key: String): String =
        fileName?.let { "${fileName}_$key" } ?: KeySafeMetadataManager.legacyEncryptedRawKey(key)

    @PublishedApi
    internal fun protectionToMetaJson(
        protection: KSafeProtection?,
        requireUnlockedDevice: Boolean? = null
    ): String {
        val accessPolicy = if (protection == null) {
            null
        } else {
            KeySafeMetadataManager.accessPolicyFor(requireUnlockedDevice == true)
        }
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
        val bytes = secureRandomBytes(16)
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
        val protectionByKey = mutableMapOf<String, KSafeProtection>()

        preferences.asMap().forEach { (prefKey, prefValue) ->
            val keyName = prefKey.name
            when {
                keyName.startsWith(KeySafeMetadataManager.META_PREFIX) && keyName.endsWith(KeySafeMetadataManager.META_SUFFIX) -> {
                    val userKey = keyName
                        .removePrefix(KeySafeMetadataManager.META_PREFIX)
                        .removeSuffix(KeySafeMetadataManager.META_SUFFIX)
                    KeySafeMetadataManager.parseProtection(prefValue as? String)?.let { protectionByKey[userKey] = it }
                }
                KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) != null -> {
                    val userKey = KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) ?: return@forEach
                    if (!protectionByKey.containsKey(userKey)) {
                        KeySafeMetadataManager.parseProtection(prefValue as? String)?.let { protectionByKey[userKey] = it }
                    }
                }
            }
        }

        preferences.asMap().forEach { (key, _) ->
            val keyName = key.name
            when {
                keyName.startsWith(fileName?.let { "${fileName}_" } ?: "encrypted_") -> {
                    val keyId = keyName.removePrefix(fileName?.let { "${fileName}_" } ?: "encrypted_")
                    validKeys.add(keyId)
                }
                keyName.startsWith(KeySafeMetadataManager.VALUE_PREFIX) -> {
                    val keyId = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                    if (protectionByKey[keyId] != null) {
                        validKeys.add(keyId)
                    }
                }
            }
        }

        // Find and remove all Keychain entries that don't have corresponding data
        removeOrphanedKeychainKeys(validKeys)
    }

    /**
     * Remove Keychain entries that don't have corresponding encrypted data in DataStore.
     *
     * Scans two Keychain item classes:
     * 1. `kSecClassGenericPassword` — discovers plain AES keys and SE-wrapped AES keys
     * 2. `kSecClassKey` — discovers orphaned SE EC private keys that may exist
     *    without a corresponding generic-password item (e.g., crash between SE key
     *    creation and wrapped-key storage)
     *
     * Uses [engine.deleteKey] which unconditionally cleans up all three artifact types
     * (plain key + SE-wrapped key + SE EC key) per identifier.
     */
    @OptIn(ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)
    private fun removeOrphanedKeychainKeys(validKeys: Set<String>) {
        val basePrefix = listOfNotNull(KEY_PREFIX, fileName).joinToString(".")
        val prefixWithDelimiter = "$basePrefix."
        val sePrefixWithDelimiter = "${IosKeychainEncryption.SE_KEY_TAG_PREFIX}$prefixWithDelimiter"

        val orphanedKeyIds = mutableSetOf<String>()

        // --- Scan 1: generic-password items (plain keys + SE-wrapped keys) ---
        memScoped {
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
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
                            ?: continue

                        // Match plain keys: {prefix}.{keyId}
                        if (account.startsWith(prefixWithDelimiter)) {
                            val keyId = account.removePrefix(prefixWithDelimiter)
                            if (fileName == null && keyId.contains('.')) continue
                            if (keyId !in validKeys) orphanedKeyIds.add(keyId)
                        }
                        // Match SE-wrapped keys: se.{prefix}.{keyId}
                        else if (account.startsWith(sePrefixWithDelimiter)) {
                            val keyId = account.removePrefix(sePrefixWithDelimiter)
                            if (fileName == null && keyId.contains('.')) continue
                            if (keyId !in validKeys) orphanedKeyIds.add(keyId)
                        }
                    }
                }
            }
        }

        // --- Scan 2: kSecClassKey items (SE EC private keys) ---
        // Catches orphaned SE keys that exist without a matching generic-password item,
        // e.g., if a crash occurred between SE key creation and wrapped-key storage.
        memScoped {
            val query = CFDictionaryCreateMutable(
                kCFAllocatorDefault, 0, null, null
            ).apply {
                CFDictionarySetValue(this, kSecClass, kSecClassKey)
                CFDictionarySetValue(this, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
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
                        // SE EC keys use applicationTag (NSData) not account (NSString)
                        val tagData = dict?.objectForKey(kSecAttrApplicationTag as Any)
                            as? platform.Foundation.NSData ?: continue
                        val tagBytes = ByteArray(tagData.length.toInt())
                        if (tagBytes.isNotEmpty()) {
                            tagBytes.usePinned { pinned ->
                                platform.posix.memcpy(pinned.addressOf(0), tagData.bytes, tagData.length)
                            }
                        }
                        val tag = tagBytes.decodeToString()

                        // Match SE tags: se.{prefix}.{keyId}
                        if (tag.startsWith(sePrefixWithDelimiter)) {
                            val keyId = tag.removePrefix(sePrefixWithDelimiter)
                            if (fileName == null && keyId.contains('.')) continue
                            if (keyId !in validKeys) orphanedKeyIds.add(keyId)
                        }
                    }
                }
            }
        }

        // Delete all artifacts for each orphaned key via engine.
        // engine.deleteKey unconditionally handles plain key + SE-wrapped key + SE EC key.
        for (keyId in orphanedKeyIds) {
            val fullIdentifier = "$prefixWithDelimiter$keyId"
            engine.deleteKey(fullIdentifier)
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
        val currentDirty: Set<String> = dirtyKeys.value
        val existingMetadata = protectionMap.value

        fun isDirtyForUserKey(userKey: String): Boolean {
            val legacyEncrypted = legacyEncryptedRawKey(userKey)
            return currentDirty.contains(userKey)
                || currentDirty.contains(legacyEncrypted)
                || currentDirty.contains(valueRawKey(userKey))
        }

        val metadataEntries = prefsMap.map { (prefKey, prefValue) -> prefKey.name to (prefValue as? String) }
        val protectionByKey = KeySafeMetadataManager.collectMetadata(
            entries = metadataEntries,
            accept = { userKey -> !isDirtyForUserKey(userKey) }
        ).toMutableMap()

        val newCache = mutableMapOf<String, Any>()
        val validKeys = mutableSetOf<String>()
        val legacyEncryptedPrefix = fileName?.let { "${fileName}_" } ?: KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX

        for ((prefKey, prefValue) in prefsMap) {
            val keyName = prefKey.name
            val classified = KeySafeMetadataManager.classifyStorageEntry(
                rawKey = keyName,
                legacyEncryptedPrefix = legacyEncryptedPrefix,
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
                validKeys.add(cacheKey)
                continue
            }

            validKeys.add(cacheKey)

            if (explicitEncrypted == true) {
                val encryptedString = prefValue as? String ?: continue
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                    newCache[cacheKey] = encryptedString
                } else {
                    try {
                        val ciphertext = decodeBase64(encryptedString)
                        val keyId = listOfNotNull(KEY_PREFIX, fileName, userKey).joinToString(".")
                        val decryptedBytes = engine.decrypt(keyId, ciphertext)
                        newCache[cacheKey] = decryptedBytes.decodeToString()
                    } catch (e: IllegalStateException) {
                        if (e.message?.contains("device is locked") == true ||
                            e.message?.contains("Keychain") == true) {
                            throw e
                        }
                    } catch (_: Exception) { }
                }
            } else {
                newCache[cacheKey] = prefValue
            }
        }

        validKeys.addAll(currentDirty)
        val keysToRemove = memoryCache.value.keys.filter { it !in validKeys }

        while (true) {
            val current = memoryCache.value
            val merged = current.toMutableMap()
            for ((k, v) in newCache) {
                if (k !in currentDirty) merged[k] = v
            }
            for (k in keysToRemove) {
                if (k !in currentDirty) merged.remove(k)
            }
            if (memoryCache.compareAndSet(current, merged)) break
        }

        while (true) {
            val currentMeta = protectionMap.value
            val mergedMeta = currentMeta.toMutableMap()
            for ((k, v) in protectionByKey) {
                if (!isDirtyForUserKey(k)) mergedMeta[k] = KeySafeMetadataManager.extractProtectionLiteral(v)
            }
            for (k in currentMeta.keys) {
                if (!protectionByKey.containsKey(k) && !isDirtyForUserKey(k)) {
                    mergedMeta.remove(k)
                }
            }
            if (protectionMap.compareAndSet(currentMeta, mergedMeta)) break
        }

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

    @PublishedApi internal inline fun <reified T> resolveFromCache(cache: Map<String, Any>, key: String, defaultValue: T, protection: KSafeProtection?): T {
        @Suppress("UNCHECKED_CAST")
        return resolveFromCacheRaw(cache, key, defaultValue, protection, serializer<T>()) as T
    }

    /**
     * Non-inline version of [resolveFromCache]. All cache lookup, decryption,
     * Base64 decode and timed-cache logic lives here. Returns raw [Any?].
     */
    @PublishedApi
    internal fun resolveFromCacheRaw(cache: Map<String, Any>, key: String, defaultValue: Any?, protection: KSafeProtection?, serializer: KSerializer<*>): Any? {
        val cacheKey = if (protection != null) legacyEncryptedRawKey(key) else key
        val cachedValue = cache[cacheKey] ?: return defaultValue

        return if (protection != null) {
            var jsonString: String? = null
            var deserializedValue: Any? = null
            var success = false

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                    val cached = plaintextCache.value[cacheKey]
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
                        val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
                        val decryptedBytes = engine.decrypt(keyId, ciphertext)
                        val candidateJson = decryptedBytes.decodeToString()

                        deserializedValue = if (candidateJson == NULL_SENTINEL) null
                            else jsonDecode(json, serializer, candidateJson)
                        success = true

                        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                            val newMap = plaintextCache.value.toMutableMap()
                            newMap[cacheKey] = CachedPlaintext(candidateJson, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
                            plaintextCache.value = newMap
                        }
                    }
                } catch (e: IllegalStateException) {
                    if (e.message?.contains("device is locked") == true ||
                        e.message?.contains("Keychain") == true) {
                        throw e
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

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal inline fun <reified T> convertStoredValue(storedValue: Any?, defaultValue: T): T {
        return convertStoredValueRaw(storedValue, defaultValue, serializer<T>()) as T
    }

    /**
     * Non-inline version of [convertStoredValue]. Handles primitive type branches
     * without reified T; uses [serializer] for the JSON `else` branch.
     */
    @Suppress("UNCHECKED_CAST")
    @PublishedApi
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
                if (storedValue !is String) return storedValue
                if (storedValue == NULL_SENTINEL) return null
                if (isStringSerializer(serializer)) return storedValue
                try { jsonDecode(json, serializer, storedValue) } catch (_: Exception) { defaultValue }
            }
        }
    }

    // ----- Unencrypted Storage Functions -----

    @PublishedApi
    internal suspend fun getUnencryptedRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (cacheInitialized.value) {
            return resolveFromCacheRaw(memoryCache.value, key, defaultValue, protection = null, serializer)
        }
        ensureCleanupPerformed()
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return resolveFromCacheRaw(memoryCache.value, key, defaultValue, protection = null, serializer)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        return getUnencryptedRaw(key, defaultValue, serializer<T>()) as T
    }

    @PublishedApi
    internal suspend fun putUnencryptedRaw(key: String, value: Any?, serializer: KSerializer<*>) {
        ensureCleanupPerformed()
        addDirtyKey(key)
        while (true) {
            val current = protectionMap.value
            val updated = current + (key to KeySafeMetadataManager.protectionToLiteral(null))
            if (protectionMap.compareAndSet(current, updated)) break
        }

        if (value == null) {
            val preferencesKey = stringPreferencesKey(valueRawKey(key))
            dataStore.edit { preferences ->
                preferences[preferencesKey] = NULL_SENTINEL
                preferences[metaPrefKey(key)] = protectionToMetaJson(null)
                preferences.removeAllLegacyKeys(key)
            }
            updateMemoryCache(key, NULL_SENTINEL)
            return
        }

        @Suppress("UNCHECKED_CAST")
        val preferencesKey: Preferences.Key<Any> = when (value) {
            is Boolean -> booleanPreferencesKey(valueRawKey(key))
            is Int -> intPreferencesKey(valueRawKey(key))
            is Long -> longPreferencesKey(valueRawKey(key))
            is Float -> floatPreferencesKey(valueRawKey(key))
            is Double -> doublePreferencesKey(valueRawKey(key))
            is String -> stringPreferencesKey(valueRawKey(key))
            else -> stringPreferencesKey(valueRawKey(key))
        } as Preferences.Key<Any>

        val storedValue: Any = when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> value
            else -> jsonEncode(json, serializer, value)
        }

        dataStore.edit { preferences ->
            preferences[preferencesKey] = storedValue
            preferences[metaPrefKey(key)] = protectionToMetaJson(null)
            preferences.removeAllLegacyKeys(key)
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

    // ----- Encryption Helpers -----

    @PublishedApi
    internal fun encryptedPrefKey(key: String) =
        legacyEncryptedPrefKey(key)

    /**
     * DataStore key for per-key protection metadata.
     * Records whether a key was encrypted with DEFAULT or HARDWARE_ISOLATED,
     * enabling correct re-encryption if migration ever requires it.
     */
    @PublishedApi
    internal fun protectionMetaKey(key: String) =
        legacyProtectionMetaKey(key)

    @PublishedApi
    internal fun detectProtection(key: String): KSafeProtection? {
        val meta = protectionMap.value[key]
        KeySafeMetadataManager.parseProtection(meta)?.let { return it }
        // Fallback heuristic (legacy data without metadata)
        val encKey = legacyEncryptedRawKey(key)
        return if (memoryCache.value.containsKey(encKey)) KSafeProtection.DEFAULT
        else null
    }

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

    suspend fun storeEncryptedData(
        key: String,
        data: ByteArray,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean = false
    ) {
        val encoded = encodeBase64(data)
        dataStore.edit { preferences ->
            preferences[valuePrefKey(key)] = encoded
            preferences[metaPrefKey(key)] = protectionToMetaJson(
                protection = if (hardwareIsolated) KSafeProtection.HARDWARE_ISOLATED else KSafeProtection.DEFAULT,
                requireUnlockedDevice = requireUnlockedDevice
            )
            preferences.removeAllLegacyKeys(key)
        }
    }

    @PublishedApi
    internal suspend fun putEncryptedRaw(
        key: String,
        value: Any?,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean,
        serializer: KSerializer<*>
    ) {
        ensureCleanupPerformed()
        val rawKeyForDirty = legacyEncryptedRawKey(key)
        addDirtyKey(rawKeyForDirty)
        while (true) {
            val current = protectionMap.value
            val updated = current + (
                key to KeySafeMetadataManager.protectionToLiteral(
                    if (hardwareIsolated) KSafeProtection.HARDWARE_ISOLATED else KSafeProtection.DEFAULT
                )
            )
            if (protectionMap.compareAndSet(current, updated)) break
        }

        val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
        val plaintext = jsonString.encodeToByteArray()

        val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
        val ciphertext = withContext(Dispatchers.Default) {
            engine.encrypt(
                identifier = keyId,
                data = plaintext,
                hardwareIsolated = hardwareIsolated,
                requireUnlockedDevice = requireUnlockedDevice
            )
        }

        storeEncryptedData(key, ciphertext, hardwareIsolated, requireUnlockedDevice)

        val rawKey = legacyEncryptedRawKey(key)
        val cacheValue = if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
            encodeBase64(ciphertext)
        } else {
            jsonString
        }
        updateMemoryCache(rawKey, cacheValue)

        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
            val newMap = plaintextCache.value.toMutableMap()
            newMap[rawKey] = CachedPlaintext(jsonString, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
            plaintextCache.value = newMap
        }
    }

    suspend inline fun <reified T> putEncrypted(
        key: String,
        value: T,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean = false
    ) {
        putEncryptedRaw(key, value, hardwareIsolated, requireUnlockedDevice, serializer<T>())
    }

    @PublishedApi
    internal suspend fun getEncryptedRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (cacheInitialized.value) {
            return withContext(Dispatchers.Default) {
                resolveFromCacheRaw(memoryCache.value, key, defaultValue, protection = KSafeProtection.DEFAULT, serializer)
            }
        }
        ensureCleanupPerformed()
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return withContext(Dispatchers.Default) {
            resolveFromCacheRaw(memoryCache.value, key, defaultValue, protection = KSafeProtection.DEFAULT, serializer)
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
        if (!cacheInitialized.value) {
            val prefs = dataStore.data.first()
            updateCache(prefs)
        }
        val detected = detectProtection(key)
        val resolved = resolveProtection(detected)
        return if (resolved != null) getEncryptedRaw(key, defaultValue, serializer) else getUnencryptedRaw(key, defaultValue, serializer)
    }

    actual inline fun <reified T> getDirect(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return getDirectRaw(key, defaultValue, serializer<T>()) as T
    }

    @PublishedApi
    internal actual fun getDirectRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (!cacheInitialized.value) {
            runBlocking {
                if (!cacheInitialized.value) {
                    val prefs = dataStore.data.first()
                    updateCache(prefs)
                }
            }
        }
        val detected = detectProtection(key)
        val resolved = resolveProtection(detected)
        return resolveFromCacheRaw(memoryCache.value, key, defaultValue, resolved, serializer)
    }


    @Suppress("UNCHECKED_CAST")
    @PublishedApi internal inline fun <reified T> getUnencryptedFlow(key: String, defaultValue: T): Flow<T> {
        return getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
    }

    @PublishedApi internal inline fun <reified T> getEncryptedFlow(key: String, defaultValue: T): Flow<T> {
        @Suppress("UNCHECKED_CAST")
        return getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
    }

    @Suppress("unused")
    actual inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> {
        @Suppress("UNCHECKED_CAST")
        return getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
    }

    @PublishedApi
    internal actual fun getFlowRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Flow<Any?> {
        writeScope.launch {
            ensureCleanupPerformed()
        }
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
                            val ciphertext = decodeBase64(enc)
                            val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
                            val decryptedBytes = engine.decrypt(keyId, ciphertext)
                            val jsonString = decryptedBytes.decodeToString()
                            if (jsonString == NULL_SENTINEL) null
                            else jsonDecode(json, serializer, jsonString)
                        } catch (e: IllegalStateException) {
                            if (e.message?.contains("device is locked") == true ||
                                e.message?.contains("Keychain") == true) throw e
                            defaultValue
                        } catch (_: Exception) { defaultValue }
                    } else defaultValue
                }
            }
        }.distinctUntilChanged()
    }

    actual suspend inline fun <reified T> put(key: String, value: T) {
        putRaw(key, value, defaultEncryptedMode(), serializer<T>())
    }

    actual suspend inline fun <reified T> put(key: String, value: T, mode: KSafeWriteMode) {
        putRaw(key, value, mode, serializer<T>())
    }

    @PublishedApi
    internal actual suspend fun putRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) {
        val resolved = resolveProtection(mode.toProtection())
        if (resolved != null) {
            putEncryptedRaw(
                key = key,
                value = value,
                hardwareIsolated = resolved == KSafeProtection.HARDWARE_ISOLATED,
                requireUnlockedDevice = mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice,
                serializer = serializer
            )
        } else {
            putUnencryptedRaw(key, value, serializer)
        }
    }

    actual inline fun <reified T> putDirect(key: String, value: T) {
        putDirectRaw(key, value, defaultEncryptedMode(), serializer<T>())
    }

    actual inline fun <reified T> putDirect(key: String, value: T, mode: KSafeWriteMode) {
        putDirectRaw(key, value, mode, serializer<T>())
    }

    @PublishedApi
    internal actual fun putDirectRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) {
        val resolved = resolveProtection(mode.toProtection())
        val requireUnlockedDevice = mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice
        val rawKey = if (resolved != null) legacyEncryptedRawKey(key) else key
        addDirtyKey(rawKey)

        if (resolved != null) {
            val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
            val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")

            updateMemoryCache(rawKey, jsonString)

            while (true) {
                val current = protectionMap.value
                val protLiteral = KeySafeMetadataManager.protectionToLiteral(
                    if (resolved == KSafeProtection.HARDWARE_ISOLATED) KSafeProtection.HARDWARE_ISOLATED
                    else KSafeProtection.DEFAULT
                )
                val updated = current + (key to protLiteral)
                if (protectionMap.compareAndSet(current, updated)) break
            }

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                val newMap = plaintextCache.value.toMutableMap()
                newMap[rawKey] = CachedPlaintext(jsonString, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
                plaintextCache.value = newMap
            }

            writeChannel.trySend(
                WriteOperation.Encrypted(
                    rawKey = rawKey,
                    key = key,
                    jsonString = jsonString,
                    keyId = keyId,
                    hardwareIsolated = resolved == KSafeProtection.HARDWARE_ISOLATED,
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

            while (true) {
                val current = protectionMap.value
                val updated = current + (key to KeySafeMetadataManager.protectionToLiteral(null))
                if (protectionMap.compareAndSet(current, updated)) break
            }

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

    /**
     * Deletes a value from DataStore.
     *
     * @param key The key of the value to delete.
     */
    actual suspend fun delete(key: String) {
        dataStore.edit { preferences ->
            preferences.removeByKeyName(valueRawKey(key))
            preferences.remove(metaPrefKey(key))
            preferences.removeAllLegacyKeys(key)
        }

        // Delete the encryption key using the engine
        val keyId = listOfNotNull(KEY_PREFIX, fileName, key).joinToString(".")
        engine.deleteKey(keyId)

        val encKeyName = legacyEncryptedRawKey(key)
        updateMemoryCache(key, null)
        updateMemoryCache(encKeyName, null)

        // Clear from plaintext cache
        val newMap = plaintextCache.value.toMutableMap()
        newMap.remove(key)
        newMap.remove(encKeyName)
        plaintextCache.value = newMap

        // Remove protection metadata
        while (true) {
            val current = protectionMap.value
            val updated = current - key
            if (protectionMap.compareAndSet(current, updated)) break
        }
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
        val encKeyName = legacyEncryptedRawKey(key)

        // Mark keys as dirty
        addDirtyKey(rawKey)
        addDirtyKey(encKeyName)

        // Optimistic cache update
        updateMemoryCache(key, null)
        updateMemoryCache(encKeyName, null)

        // Clear from plaintext cache
        val newPtMap = plaintextCache.value.toMutableMap()
        newPtMap.remove(rawKey)
        newPtMap.remove(encKeyName)
        plaintextCache.value = newPtMap

        // Remove protection metadata
        while (true) {
            val current = protectionMap.value
            val updated = current - key
            if (protectionMap.compareAndSet(current, updated)) break
        }

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

        val protectionByKey = mutableMapOf<String, KSafeProtection>()
        for ((prefKey, prefValue) in preferences.asMap()) {
            val keyName = prefKey.name
            when {
                keyName.startsWith(KeySafeMetadataManager.META_PREFIX) && keyName.endsWith(KeySafeMetadataManager.META_SUFFIX) -> {
                    val userKey = keyName
                        .removePrefix(KeySafeMetadataManager.META_PREFIX)
                        .removeSuffix(KeySafeMetadataManager.META_SUFFIX)
                    KeySafeMetadataManager.parseProtection(prefValue as? String)?.let { protectionByKey[userKey] = it }
                }
                KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) != null -> {
                    val userKey = KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) ?: continue
                    if (!protectionByKey.containsKey(userKey)) {
                        KeySafeMetadataManager.parseProtection(prefValue as? String)?.let { protectionByKey[userKey] = it }
                    }
                }
            }
        }

        preferences.asMap().forEach { (key, _) ->
            val keyName = key.name
            when {
                keyName.startsWith(fileName?.let { "${fileName}_" } ?: "encrypted_") -> {
                    encryptedKeys.add(keyName.removePrefix(fileName?.let { "${fileName}_" } ?: "encrypted_"))
                }
                keyName.startsWith(KeySafeMetadataManager.VALUE_PREFIX) -> {
                    val userKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                    if (protectionByKey[userKey] != null) {
                        encryptedKeys.add(userKey)
                    }
                }
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
        plaintextCache.value = emptyMap()
        protectionMap.value = emptyMap()
    }

    // --- PER-KEY STORAGE QUERY ---

    actual fun getKeyInfo(key: String): KSafeKeyInfo? {
        if (!cacheInitialized.value) {
            runBlocking {
                if (!cacheInitialized.value) {
                    val prefs = dataStore.data.first()
                    updateCache(prefs)
                }
            }
        }

        val currentCache = memoryCache.value
        val encKey = legacyEncryptedRawKey(key)
        val hasEncrypted = currentCache.containsKey(encKey)
        val hasPlain = currentCache.containsKey(key)
        if (!hasEncrypted && !hasPlain) return null
        if (!hasEncrypted) return KSafeKeyInfo(null, KSafeKeyStorage.SOFTWARE)

        val protection = KeySafeMetadataManager.parseProtection(protectionMap.value[key]) ?: KSafeProtection.DEFAULT
        val storage = when (protection) {
            KSafeProtection.HARDWARE_ISOLATED -> {
                if (KSafeKeyStorage.HARDWARE_ISOLATED in deviceKeyStorages) KSafeKeyStorage.HARDWARE_ISOLATED
                else KSafeKeyStorage.HARDWARE_BACKED
            }
            else -> KSafeKeyStorage.HARDWARE_BACKED
        }
        return KSafeKeyInfo(protection, storage)
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
