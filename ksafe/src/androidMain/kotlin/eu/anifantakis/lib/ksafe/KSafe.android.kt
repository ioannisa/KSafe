package eu.anifantakis.lib.ksafe

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
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
 * @property useStrongBox **Deprecated.** Prefer per-property [KSafeProtection.HARDWARE_ISOLATED].
 *   When true, [KSafeProtection.DEFAULT] is automatically promoted to [KSafeProtection.HARDWARE_ISOLATED].
 *   Existing keys are unaffected — they remain in whatever hardware they were originally generated in.
 */
actual class KSafe(
    private val context: Context,
    @PublishedApi internal val fileName: String? = null,
    private val lazyLoad: Boolean = false,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
    private val config: KSafeConfig = KSafeConfig(),
    private val securityPolicy: KSafeSecurityPolicy = KSafeSecurityPolicy.Default,
    @PublishedApi internal val plaintextCacheTtl: Duration = 5.seconds,
    @Deprecated("Use KSafeProtection.HARDWARE_ISOLATED per-property instead")
    private val useStrongBox: Boolean = false
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
        useStrongBox: Boolean = false,
        testEngine: KSafeEncryption
    ) : this(context, fileName, lazyLoad, memoryPolicy, config, securityPolicy, plaintextCacheTtl, useStrongBox) {
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

    private val hasStrongBox: Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    actual val deviceKeyStorages: Set<KSafeKeyStorage> = buildSet {
        add(KSafeKeyStorage.HARDWARE_BACKED)
        if (hasStrongBox) add(KSafeKeyStorage.HARDWARE_ISOLATED)
    }

    @Suppress("DEPRECATION")
    @PublishedApi
    internal fun resolveProtection(protection: KSafeProtection): KSafeProtection =
        if (protection == KSafeProtection.DEFAULT && useStrongBox) KSafeProtection.HARDWARE_ISOLATED
        else protection

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
     * Per-key protection metadata cache.
     * Maps user key to protection level string ("DEFAULT" or "HARDWARE_ISOLATED").
     * Populated from `__ksafe_prot_{key}__` entries in DataStore.
     */
    @PublishedApi
    internal val protectionMap = ConcurrentHashMap<String, String>()

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
            val keyAlias: String,
            val hardwareIsolated: Boolean = false
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
                val ciphertext = engine.encrypt(op.keyAlias, op.jsonString.encodeToByteArray(), op.hardwareIsolated)
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
                        prefs[metaPrefKey(op.key)] = protectionToMetaJson(KSafeProtection.NONE)
                        prefs.removeAllLegacyKeys(op.key)
                    }
                    is WriteOperation.Encrypted -> {
                        val ciphertext = encryptedData[op.key]!!
                        prefs[valuePrefKey(op.key)] = encodeBase64(ciphertext)
                        prefs[metaPrefKey(op.key)] = protectionToMetaJson(
                            if (op.hardwareIsolated) KSafeProtection.HARDWARE_ISOLATED else KSafeProtection.DEFAULT
                        )
                        prefs.removeAllLegacyKeys(op.key)
                    }
                    is WriteOperation.Delete -> {
                        prefs.removeByKeyName(valueRawKey(op.key))
                        prefs.remove(metaPrefKey(op.key))
                        prefs.removeAllLegacyKeys(op.key)
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
        val orphanedKeys = mutableListOf<String>()
        val protectionByKey = mutableMapOf<String, KSafeProtection>()

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

        fun isMissingKeyError(message: String): Boolean {
            return message.contains("No encryption key found", ignoreCase = true) ||
                message.contains("key not found", ignoreCase = true)
        }

        for ((prefKey, prefValue) in prefs.asMap()) {
            val keyName = prefKey.name

            // Legacy encrypted entries are preserved to avoid destructive cleanup on upgrades.
            if (keyName.startsWith(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX)) continue

            if (!keyName.startsWith(KeySafeMetadataManager.VALUE_PREFIX)) continue
            val originalKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)

            val protection = protectionByKey[originalKey]
            // Missing/unknown metadata: do not delete blindly.
            if (protection == null || protection == KSafeProtection.NONE) continue

            val encryptedString = prefValue as? String ?: continue
            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, originalKey).joinToString(".")

            try {
                val ciphertext = decodeBase64(encryptedString)
                engine.decrypt(keyAlias, ciphertext)
            } catch (e: Exception) {
                val msg = e.message ?: ""
                if (msg.contains("device is locked", ignoreCase = true) ||
                    msg.contains("Keystore", ignoreCase = true)) continue

                // Only delete when the key is definitely gone.
                if (isMissingKeyError(msg)) {
                    orphanedKeys.add(keyName)
                }
            }
        }

        if (orphanedKeys.isNotEmpty()) {
            dataStore.edit { mutablePrefs ->
                for (keyName in orphanedKeys) {
                    mutablePrefs.removeByKeyName(keyName)
                    val originalKey = keyName
                        .removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                    mutablePrefs.remove(metaPrefKey(originalKey))
                    mutablePrefs.remove(legacyProtectionMetaKey(originalKey))
                }
            }
            for (keyName in orphanedKeys) {
                val originalKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                memoryCache.remove(originalKey)
                memoryCache.remove(legacyEncryptedRawKey(originalKey))
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
        val protectionByKey = mutableMapOf<String, KSafeProtection>()

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

        // Phase 1: Decrypt all values first — no Keystore mutations
        val decryptedData = mutableMapOf<String, Pair<String, ByteArray>>() // keyName → (keyAlias, plaintext)
        for ((prefKey, prefValue) in prefs.asMap()) {
            val keyName = prefKey.name
            val originalKey = when {
                keyName.startsWith(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX) ->
                    keyName.removePrefix(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX)
                keyName.startsWith(KeySafeMetadataManager.VALUE_PREFIX) -> {
                    val userKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                    if (protectionByKey[userKey] != KSafeProtection.NONE) userKey else continue
                }
                else -> continue
            }

            val encryptedString = prefValue as? String ?: continue
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
        // Per-key protection metadata (1.7.0+) determines the correct hardware isolation
        // level for each key during re-encryption. Pre-1.7.0 keys without metadata fall
        // back to the global constructor flag.
        @Suppress("DEPRECATION")
        val globalHardwareIsolated = useStrongBox && hasStrongBox
        val reEncrypted = mutableMapOf<String, String>()
        val resolvedMeta = mutableMapOf<String, Boolean>() // originalKey -> hardwareIsolated
        for ((keyName, pair) in decryptedData) {
            val (keyAlias, plaintext) = pair
            val originalKey = when {
                keyName.startsWith(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX) ->
                    keyName.removePrefix(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX)
                keyName.startsWith(KeySafeMetadataManager.VALUE_PREFIX) ->
                    keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                else -> continue
            }
            val protection = protectionByKey[originalKey]
            val keyHardwareIsolated = when (protection) {
                KSafeProtection.HARDWARE_ISOLATED -> true
                KSafeProtection.DEFAULT -> false
                else -> globalHardwareIsolated
            }
            try {
                engine.deleteKey(keyAlias)
                val newCiphertext = engine.encrypt(keyAlias, plaintext, keyHardwareIsolated)
                reEncrypted[keyName] = encodeBase64(newCiphertext)
                resolvedMeta[originalKey] = keyHardwareIsolated
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
            // Persist per-key metadata so future migrations don't rely on global fallback
            for ((originalKey, hardwareIsolated) in resolvedMeta) {
                mutablePrefs[metaPrefKey(originalKey)] = protectionToMetaJson(
                    if (hardwareIsolated) KSafeProtection.HARDWARE_ISOLATED else KSafeProtection.DEFAULT
                )
                mutablePrefs.remove(legacyProtectionMetaKey(originalKey))
            }
            mutablePrefs[markerKey] = targetPolicy
        }
    }

    @PublishedApi
    internal fun valueRawKey(key: String): String = KeySafeMetadataManager.valueRawKey(key)

    @PublishedApi
    internal fun valuePrefKey(key: String) = stringPreferencesKey(valueRawKey(key))

    @PublishedApi
    internal fun metaPrefKey(key: String) = stringPreferencesKey(KeySafeMetadataManager.metadataRawKey(key))

    @PublishedApi
    internal fun legacyEncryptedPrefKey(key: String) = stringPreferencesKey(KeySafeMetadataManager.legacyEncryptedRawKey(key))

    @PublishedApi
    internal fun legacyProtectionMetaKey(key: String) = stringPreferencesKey(KeySafeMetadataManager.legacyProtectionRawKey(key))

    @PublishedApi
    internal fun legacyEncryptedRawKey(key: String): String = KeySafeMetadataManager.legacyEncryptedRawKey(key)

    @PublishedApi
    internal fun protectionToMetaJson(protection: KSafeProtection): String {
        val accessPolicy = if (config.requireUnlockedDevice) ACCESS_POLICY_UNLOCKED else ACCESS_POLICY_DEFAULT
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
        val currentDirty: Set<String> = try { HashSet(dirtyKeys) } catch (_: Exception) { emptySet() }
        val existingMetadata = HashMap(protectionMap)
        val validCacheKeys = mutableSetOf<String>()

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

        // Pass 2: load values (canonical + legacy fallback)
        for ((prefKey, prefValue) in prefsMap) {
            val keyName = prefKey.name
            val classified = KeySafeMetadataManager.classifyStorageEntry(
                rawKey = keyName,
                legacyEncryptedPrefix = KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX,
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
                validCacheKeys.add(cacheKey)
                continue
            }

            validCacheKeys.add(cacheKey)

            if (explicitEncrypted == true) {
                val encryptedString = prefValue as? String ?: continue
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                    memoryCache[cacheKey] = encryptedString
                } else {
                    try {
                        val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, userKey).joinToString(".")
                        val encryptedBytes = decodeBase64(encryptedString)
                        val decryptedBytes = engine.decrypt(keyAlias, encryptedBytes)
                        memoryCache[cacheKey] = decryptedBytes.decodeToString()
                    } catch (_: Exception) { }
                }
            } else {
                memoryCache[cacheKey] = prefValue
            }
        }

        validCacheKeys.addAll(currentDirty)

        try {
            val keysToRemove = memoryCache.keys.filter { it !in validCacheKeys && !dirtyKeys.contains(it) }
            keysToRemove.forEach { memoryCache.remove(it) }
        } catch (_: Exception) { }

        val existingMetaKeys = protectionMap.keys.toList()
        for ((userKey, rawMeta) in protectionByKey) {
            if (!isDirtyForUserKey(userKey)) {
                protectionMap[userKey] = rawMeta
            }
        }
        for (userKey in existingMetaKeys) {
            if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKey(userKey)) {
                protectionMap.remove(userKey)
            }
        }

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
    internal inline fun <reified T> resolveFromCache(cache: Map<String, Any>, key: String, defaultValue: T, protection: KSafeProtection): T {
        // Determine internal key format used in cache (isomorphic to disk keys)
        val cacheKey = if (protection != KSafeProtection.NONE) legacyEncryptedRawKey(key) else key
        val cachedValue = cache[cacheKey] ?: return defaultValue

        return if (protection != KSafeProtection.NONE) {
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

    actual inline fun <reified T> getDirect(key: String, defaultValue: T): T {
        // Ensure cache is ready
        if (!cacheInitialized.get()) {
            runBlocking {
                if (!cacheInitialized.get()) {
                    val prefs = dataStore.data.first()
                    updateCache(prefs)
                }
            }
        }
        val detected = detectProtection(key)
        val resolved = resolveProtection(detected)
        return resolveFromCache(memoryCache, key, defaultValue, resolved)
    }


    actual inline fun <reified T> putDirect(key: String, value: T, protection: KSafeProtection) {
        val resolved = resolveProtection(protection)
        val rawKey = if (resolved != KSafeProtection.NONE) "encrypted_$key" else key

        // 1. Mark key as dirty to prevent overwrite by background observer
        addDirtyKey(rawKey)

        // 2. Optimistic update + queue write operation
        if (resolved != KSafeProtection.NONE) {
            // Single serialization for encrypted writes
            val jsonString = if (value == null) NULL_SENTINEL else json.encodeToString(serializer<T>(), value)
            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")

            // Cache stores plaintext JSON for instant read-back
            // (resolveFromCache handles both plaintext JSON and encrypted Base64)
            updateMemoryCache(rawKey, jsonString)

            // Update protection metadata
            protectionMap[key] = protectionToMetaJson(
                if (resolved == KSafeProtection.HARDWARE_ISOLATED) KSafeProtection.HARDWARE_ISOLATED else KSafeProtection.DEFAULT
            )

            // For TIMED_CACHE, also populate the plaintext cache
            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                plaintextCache[rawKey] = CachedPlaintext(jsonString, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
            }

            // Queue the encrypted write (encryption deferred to background)
            writeChannel.trySend(WriteOperation.Encrypted(rawKey, key, jsonString, keyAlias, resolved == KSafeProtection.HARDWARE_ISOLATED))
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

            // Store NONE metadata for unencrypted keys
            protectionMap[key] = protectionToMetaJson(KSafeProtection.NONE)

            // For unencrypted writes, determine the proper DataStore key type
            val storedValue: Any? = when (value) {
                null -> null
                is Boolean, is Int, is Long, is Float, is Double, is String -> value
                else -> json.encodeToString(serializer<T>(), value)
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

            // Queue the unencrypted write
            writeChannel.trySend(WriteOperation.Unencrypted(rawKey, key, storedValue, prefKey))
        }
    }

    // ----- Encryption Helpers -----
    @PublishedApi
    internal fun encryptedPrefKey(key: String) =
        legacyEncryptedPrefKey(key)

    /**
     * DataStore key for per-key protection metadata.
     * Records whether a key was encrypted with DEFAULT or HARDWARE_ISOLATED,
     * enabling correct re-encryption during `requireUnlockedDevice` migration.
     */
    @PublishedApi
    internal fun protectionMetaKey(key: String) =
        legacyProtectionMetaKey(key)

    @PublishedApi
    internal fun detectProtection(key: String): KSafeProtection {
        val meta = protectionMap[key]
        KeySafeMetadataManager.parseProtection(meta)?.let { return it }
        // Fallback heuristic (legacy data without metadata)
        return if (memoryCache.containsKey(legacyEncryptedRawKey(key))) KSafeProtection.DEFAULT
        else KSafeProtection.NONE
    }

    suspend fun storeEncryptedData(key: String, data: ByteArray, hardwareIsolated: Boolean = false) {
        val encoded = encodeBase64(data)
        dataStore.edit { preferences ->
            preferences[valuePrefKey(key)] = encoded
            preferences[metaPrefKey(key)] = protectionToMetaJson(
                if (hardwareIsolated) KSafeProtection.HARDWARE_ISOLATED else KSafeProtection.DEFAULT
            )
            preferences.removeAllLegacyKeys(key)
        }
    }

    suspend inline fun <reified T> putEncrypted(key: String, value: T, hardwareIsolated: Boolean = false) {
        addDirtyKey(legacyEncryptedRawKey(key))
        protectionMap[key] = protectionToMetaJson(
            if (hardwareIsolated) KSafeProtection.HARDWARE_ISOLATED else KSafeProtection.DEFAULT
        )
        // Handle null values with sentinel
        val jsonString = if (value == null) {
            NULL_SENTINEL
        } else {
            json.encodeToString(serializer<T>(), value)
        }

        // Use encryption engine (switch to Default dispatcher — encryption is CPU-bound)
        val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
        val ciphertext = withContext(Dispatchers.Default) {
            engine.encrypt(keyAlias, jsonString.encodeToByteArray(), hardwareIsolated)
        }

        storeEncryptedData(key, ciphertext, hardwareIsolated)

        // Sync cache

        // Optimistic Update:
        // If ENCRYPTED or TIMED_CACHE policy, store Ciphertext (Base64). If PLAIN, store JSON.
        val cacheValue = if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED || memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
            encodeBase64(ciphertext)
        } else {
            jsonString
        }
        updateMemoryCache(legacyEncryptedRawKey(key), cacheValue)

        // For TIMED_CACHE, also populate the plaintext cache (we already have the plaintext)
        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
            plaintextCache[legacyEncryptedRawKey(key)] = CachedPlaintext(jsonString, TimeSource.Monotonic.markNow() + plaintextCacheTtl)
        }
    }

    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        // Check cache first
        if (cacheInitialized.get()) {
            return withContext(Dispatchers.Default) {
                resolveFromCache(memoryCache, key, defaultValue, protection = KSafeProtection.DEFAULT)
            }
        }

        // Fallback to disk (ensure cache is populated)
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return withContext(Dispatchers.Default) {
            resolveFromCache(memoryCache, key, defaultValue, protection = KSafeProtection.DEFAULT)
        }
    }

    actual suspend inline fun <reified T> get(key: String, defaultValue: T): T {
        if (!cacheInitialized.get()) {
            val prefs = dataStore.data.first()
            updateCache(prefs)
        }
        val detected = detectProtection(key)
        val resolved = resolveProtection(detected)
        return if (resolved != KSafeProtection.NONE) {
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
            return resolveFromCache(memoryCache, key, defaultValue, protection = KSafeProtection.NONE)
        }

        // Fallback to disk
        val prefs = dataStore.data.first()
        updateCache(prefs)
        return resolveFromCache(memoryCache, key, defaultValue, protection = KSafeProtection.NONE)
    }

    @Suppress("UNCHECKED_CAST")
    @PublishedApi
    internal suspend inline fun <reified T> putUnencrypted(key: String, value: T) {
        addDirtyKey(key)
        protectionMap[key] = protectionToMetaJson(KSafeProtection.NONE)
        // Handle null values
        if (value == null) {
            val preferencesKey = stringPreferencesKey(valueRawKey(key))
            dataStore.edit { preferences ->
                preferences[preferencesKey] = NULL_SENTINEL
                preferences[metaPrefKey(key)] = protectionToMetaJson(KSafeProtection.NONE)
                preferences.removeAllLegacyKeys(key)
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
            preferences[metaPrefKey(key)] = protectionToMetaJson(KSafeProtection.NONE)
            preferences.removeAllLegacyKeys(key)
        }

        // Update cache
        updateMemoryCache(key, storedValue)
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

    @Suppress("UNCHECKED_CAST")
    @PublishedApi
    internal inline fun <reified T> getUnencryptedFlow(key: String, defaultValue: T): Flow<T> {
        val preferencesKey = getUnencryptedKey(key, defaultValue)
        val legacyPreferencesKey = getLegacyUnencryptedKey(key, defaultValue)
        return dataStore.data.map { preferences ->
            val storedValue = preferences[preferencesKey] ?: preferences[legacyPreferencesKey]
            convertStoredValue(storedValue, defaultValue)
        }.distinctUntilChanged()
    }

    @PublishedApi
    internal inline fun <reified T> getEncryptedFlow(key: String, defaultValue: T): Flow<T> {
        val canonicalPrefKey = valuePrefKey(key)
        val legacyPrefKey = encryptedPrefKey(key)

        return dataStore.data
            .map { preferences ->
                val encryptedValue = preferences[canonicalPrefKey] ?: preferences[legacyPrefKey]
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

    actual inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> {
        return dataStore.data.map { preferences ->
            val metaRaw = preferences[metaPrefKey(key)] ?: preferences[legacyProtectionMetaKey(key)]
            val protection = KeySafeMetadataManager.parseProtection(metaRaw)
                ?: if (preferences[encryptedPrefKey(key)] != null) KSafeProtection.DEFAULT else KSafeProtection.NONE
            when (protection) {
                KSafeProtection.NONE -> {
                    val prefKey = getUnencryptedKey(key, defaultValue)
                    val legacyPrefKey = getLegacyUnencryptedKey(key, defaultValue)
                    val plain = preferences[prefKey] ?: preferences[legacyPrefKey]
                    if (plain != null) convertStoredValue(plain, defaultValue) else defaultValue
                }
                else -> {
                    val enc = preferences[valuePrefKey(key)] ?: preferences[encryptedPrefKey(key)]
                    if (enc != null) {
                        try {
                            val ciphertext = decodeBase64(enc)
                            val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
                            val decryptedBytes = engine.decrypt(keyAlias, ciphertext)
                            val jsonString = decryptedBytes.decodeToString()
                            if (jsonString == NULL_SENTINEL) {
                                @Suppress("UNCHECKED_CAST")
                                null as T
                            } else {
                                json.decodeFromString(serializer<T>(), jsonString)
                            }
                        } catch (e: IllegalStateException) {
                            if (e.message?.contains("device is locked") == true ||
                                e.message?.contains("Keystore") == true) throw e
                            defaultValue
                        } catch (_: Exception) { defaultValue }
                    } else defaultValue
                }
            }
        }.distinctUntilChanged()
    }


    actual suspend inline fun <reified T> put(key: String, value: T, protection: KSafeProtection) {
        val resolved = resolveProtection(protection)
        if (resolved != KSafeProtection.NONE) {
            putEncrypted(key, value, resolved == KSafeProtection.HARDWARE_ISOLATED)
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
        dataStore.edit { preferences ->
            preferences.removeByKeyName(valueRawKey(key))
            preferences.remove(metaPrefKey(key))
            preferences.removeAllLegacyKeys(key)
        }

        // Delete the corresponding encryption key using the engine
        val keyAlias = listOfNotNull(KEY_ALIAS_PREFIX, fileName, key).joinToString(".")
        engine.deleteKey(keyAlias)

        // Update cache
        updateMemoryCache(key, null)
        updateMemoryCache(legacyEncryptedRawKey(key), null)
        plaintextCache.remove(key)
        plaintextCache.remove(legacyEncryptedRawKey(key))
        protectionMap.remove(key)
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
        addDirtyKey(legacyEncryptedRawKey(key))

        // Optimistic update
        updateMemoryCache(key, null)
        updateMemoryCache(legacyEncryptedRawKey(key), null)
        plaintextCache.remove(key)
        plaintextCache.remove(legacyEncryptedRawKey(key))
        protectionMap.remove(key)

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

        val protectionByKey = mutableMapOf<String, KSafeProtection>()
        for ((prefKey, prefValue) in preferences.asMap()) {
            val keyName = prefKey.name
            when {
                keyName.startsWith(KeySafeMetadataManager.META_PREFIX) && keyName.endsWith(KeySafeMetadataManager.META_SUFFIX) -> {
                    val userKey = keyName
                        .removePrefix(KeySafeMetadataManager.META_PREFIX)
                        .removeSuffix(KeySafeMetadataManager.META_SUFFIX)
                    val parsed = KeySafeMetadataManager.parseProtection(prefValue as? String)
                    if (parsed != null) protectionByKey[userKey] = parsed
                }
                KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) != null -> {
                    val userKey = KeySafeMetadataManager.tryExtractLegacyProtectionKey(keyName) ?: continue
                    if (!protectionByKey.containsKey(userKey)) {
                        val parsed = KeySafeMetadataManager.parseProtection(prefValue as? String)
                        if (parsed != null) protectionByKey[userKey] = parsed
                    }
                }
            }
        }

        preferences.asMap().forEach { (key, _) ->
            val keyName = key.name
            when {
                keyName.startsWith(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX) ->
                    encryptedKeys.add(keyName.removePrefix(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX))
                keyName.startsWith(KeySafeMetadataManager.VALUE_PREFIX) -> {
                    val userKey = keyName.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                    if (protectionByKey[userKey] != KSafeProtection.NONE) {
                        encryptedKeys.add(userKey)
                    }
                }
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
        protectionMap.clear()
    }

    // --- PER-KEY STORAGE QUERY ---

    actual fun getKeyInfo(key: String): KSafeKeyInfo? {
        if (!cacheInitialized.get()) {
            runBlocking {
                if (!cacheInitialized.get()) {
                    val prefs = dataStore.data.first()
                    updateCache(prefs)
                }
            }
        }

        val hasEncrypted = memoryCache.containsKey(legacyEncryptedRawKey(key))
        val hasPlain = memoryCache.containsKey(key)
        if (!hasEncrypted && !hasPlain) return null
        if (!hasEncrypted) return KSafeKeyInfo(KSafeProtection.NONE, KSafeKeyStorage.SOFTWARE)

        val protection = KeySafeMetadataManager.parseProtection(protectionMap[key]) ?: KSafeProtection.DEFAULT
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
    @Deprecated("Replace \"encrypted\" parameter with \"protection\" parameter. \n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeProtection.DEFAULT\nencrypted=false -> KSafeProtection.NONE\n\nNote: You don't need to include a protection reference if you aim for \"DEFAULT\" protection (it is assumed and you can omit it).", level = DeprecationLevel.WARNING)
    actual inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean): Unit =
        putDirect(key, value, if (encrypted) KSafeProtection.DEFAULT else KSafeProtection.NONE)

    @Suppress("DEPRECATION")
    @Deprecated("Remove \"encrypted\" parameter. Protection is now auto-detected during reads.  Your \"encrypted\" param is ignored.", level = DeprecationLevel.WARNING)
    actual suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean): T =
        get(key, defaultValue)

    @Suppress("DEPRECATION")
    @Deprecated("Replace \"encrypted\" parameter with \"protection\" parameter. \n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeProtection.DEFAULT\nencrypted=false -> KSafeProtection.NONE\n\nNote: You don't need to include a protection reference if you aim for \"DEFAULT\" protection (it is assumed and you can omit it).", level = DeprecationLevel.WARNING)
    actual suspend inline fun <reified T> put(key: String, value: T, encrypted: Boolean): Unit =
        put(key, value, if (encrypted) KSafeProtection.DEFAULT else KSafeProtection.NONE)

    @Suppress("DEPRECATION")
    @Deprecated("Remove \"encrypted\" parameter. Protection is now auto-detected during reads.  Your \"encrypted\" param is ignored.", level = DeprecationLevel.WARNING)
    actual inline fun <reified T> getFlow(key: String, defaultValue: T, encrypted: Boolean): Flow<T> =
        getFlow(key, defaultValue)

    // --- BIOMETRIC API ---

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
