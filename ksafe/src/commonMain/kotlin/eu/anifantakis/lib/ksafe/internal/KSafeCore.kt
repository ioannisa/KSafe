package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.KSafeKeyInfo
import eu.anifantakis.lib.ksafe.KSafeKeyStorage
import eu.anifantakis.lib.ksafe.KSafeMemoryPolicy
import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import eu.anifantakis.lib.ksafe.toProtection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlin.coroutines.cancellation.CancellationException
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.ComparableTimeMark
import kotlin.time.Duration
import kotlin.time.TimeSource

/**
 * Platform-independent orchestration engine that sits between the public [KSafe]
 * API and the two platform-specific backends:
 *
 *   - [KSafePlatformStorage] — where key/value bytes live on disk.
 *   - [KSafeEncryption]      — how values get encrypted / decrypted.
 *
 * Everything that was previously duplicated across
 * `KSafe.{android,ios,jvm,web}.kt` now lives here: the hot cache, per-frame
 * write coalescer, dirty-keys tracker, protection metadata, background preload,
 * orphan-ciphertext cleanup, and the raw `get/put/delete` API that the public
 * inline wrappers delegate to.
 *
 * The only platform-specific responsibilities left are:
 *   - Constructing the storage + engine + migration lambda (via [Factory]).
 *   - Validating security policy at construction time.
 *   - Biometric prompts (separate, not part of this class).
 *   - Reporting per-key [KSafeKeyStorage] tier (see [resolveKeyStorage]).
 */
@PublishedApi
internal class KSafeCore(
    @PublishedApi internal val storage: KSafePlatformStorage,
    /**
     * Lazily-resolved engine. A provider (rather than the engine itself) lets
     * the platform shell inject a `testEngine` via a secondary constructor
     * *after* the core has already been wired up — engine resolution is
     * deferred until the first background coroutine actually needs it.
     */
    engineProvider: () -> KSafeEncryption,
    private val config: KSafeConfig,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy,
    @PublishedApi internal val plaintextCacheTtl: Duration,
    /**
     * Resolves the storage tier reported by `getKeyInfo` for a given key +
     * protection. Platform shells inject their own (Android inspects the
     * Keystore for StrongBox; iOS inspects the Keychain for Secure Enclave).
     * JVM/WASM always report [KSafeKeyStorage.SOFTWARE].
     */
    private val resolveKeyStorage: (userKey: String, protection: KSafeProtection?) -> KSafeKeyStorage,
    /**
     * Optional per-platform migration hook run once before
     * orphan-ciphertext cleanup. iOS uses it to move keys between
     * accessibility tiers; JVM/WASM are no-ops.
     */
    private val migrateAccessPolicy: suspend () -> Unit = {},
    lazyLoad: Boolean = false,
    /**
     * Builds the Keystore/Keychain alias for a given user key. Android uses
     * `"$KEY_ALIAS_PREFIX.$fileName?.$key"`; iOS/JVM use `"$fileName?:$key"`
     * (or just `key` when `fileName` is null).
     */
    @PublishedApi internal val keyAlias: (userKey: String) -> String,
    /**
     * Prefix used to recognise legacy-format encrypted entries on disk.
     * Default is `"encrypted_"`. iOS overrides this to `"${fileName}_"` when
     * a non-null filename was set, because pre-1.8 iOS builds wrote encrypted
     * entries under that prefix instead.
     */
    private val legacyEncryptedPrefix: String = KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX,
    /**
     * Full legacy-format encrypted raw key for a user key. Default strips +
     * adds the shared `encrypted_` prefix; iOS overrides for its
     * per-filename variant.
     */
    private val legacyEncryptedKeyFor: (userKey: String) -> String =
        KeySafeMetadataManager::legacyEncryptedRawKey,
    /**
     * Optional pre-write mode transform. Android/iOS use this to honor the
     * deprecated `useStrongBox`/`useSecureEnclave` constructor flags by
     * promoting `KSafeWriteMode.Encrypted(DEFAULT)` to `HARDWARE_ISOLATED`.
     * JVM/Web pass the identity (default).
     */
    private val modeTransformer: (KSafeWriteMode) -> KSafeWriteMode = { it },
    /**
     * Optional platform-specific cleanup invoked from [cancel]. DataStore-
     * backed platforms use this to cancel the scope they passed to
     * `PreferenceDataStoreFactory.create(...)` (DataStore launches its own
     * coroutines on that scope and won't stop otherwise) and, on Android,
     * to evict the per-file entry from the process-static DataStore cache.
     * Web has no equivalent and passes the default no-op.
     */
    private val onCancel: () -> Unit = {},
) {

    @PublishedApi internal val engine: KSafeEncryption by lazy(engineProvider)

    @PublishedApi internal val json: Json = config.json

    // ---- hot cache state ----

    @PublishedApi
    internal val memoryCache = KSafeConcurrentMap<Any>()

    /** Protection literal per user key ("NONE", "DEFAULT", "HARDWARE_ISOLATED"). */
    @PublishedApi
    internal val protectionMap = KSafeConcurrentMap<String>()

    @PublishedApi
    internal class CachedPlaintext(val value: String, val expiresAt: ComparableTimeMark)

    @PublishedApi
    internal val plaintextCache = KSafeConcurrentMap<CachedPlaintext>()

    @PublishedApi
    internal val cacheInitialized = KSafeAtomicFlag(false)

    /**
     * Raw cache keys currently being written. Includes both canonical
     * (`__ksafe_value_foo`) and legacy encrypted (`encrypted_foo`) forms so
     * the background collector never stomps on an optimistic update.
     */
    @PublishedApi
    internal val dirtyKeys = KSafeConcurrentSet<String>()

    // ---- coroutine scopes ----

    private val writeScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val collectorScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    /** Logical write queue — encryption happens inside the consumer, not on UI. */
    private val writeChannel = Channel<PendingWrite>(Channel.UNLIMITED)

    private val writeCoalesceWindowMs = 16L   // ~1 frame at 60 fps
    private val maxBatchSize = 50

    init {
        startWriteConsumer()
        if (!lazyLoad) startBackgroundCollector()
    }

    // ---- pending-write sealed hierarchy ----

    private sealed class PendingWrite {
        abstract val userKey: String
        abstract val rawCacheKey: String

        data class Plain(
            override val userKey: String,
            override val rawCacheKey: String,
            /**
             * Either a primitive ([Boolean], [Int], [Long], [Float], [Double], [String])
             * or the null sentinel string. Complex `@Serializable` types are pre-encoded
             * to JSON and arrive here as [String].
             */
            val value: Any,
        ) : PendingWrite()

        data class Encrypted(
            override val userKey: String,
            override val rawCacheKey: String,
            val jsonString: String,
            val alias: String,
            val protection: KSafeProtection,
            val requireUnlockedDevice: Boolean,
        ) : PendingWrite()

        data class Delete(
            override val userKey: String,
            override val rawCacheKey: String,
        ) : PendingWrite()
    }

    // ---- key/metadata helpers (thin shims over KeySafeMetadataManager) ----

    @PublishedApi
    internal fun valueRawKey(key: String): String = KeySafeMetadataManager.valueRawKey(key)

    private fun metaRawKey(key: String): String = KeySafeMetadataManager.metadataRawKey(key)

    @PublishedApi
    internal fun legacyEncryptedRawKey(key: String): String = legacyEncryptedKeyFor(key)

    private fun legacyProtectionRawKey(key: String): String =
        KeySafeMetadataManager.legacyProtectionRawKey(key)

    private fun buildMetaJson(
        protection: KSafeProtection?,
        requireUnlockedDevice: Boolean? = null,
    ): String {
        val accessPolicy = if (protection == null) null
        else KeySafeMetadataManager.accessPolicyFor(requireUnlockedDevice == true)
        return KeySafeMetadataManager.buildMetadataJson(protection, accessPolicy)
    }

    @PublishedApi
    internal fun defaultEncryptedMode(): KSafeWriteMode =
        KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)

    // ============================================================
    // Background collector — mirrors DataStore snapshotFlow into cache
    // ============================================================

    private fun startBackgroundCollector() {
        collectorScope.launch {
            runCatching { migrateAccessPolicy() }
                .onFailure { if (it is CancellationException) throw it }
            runCatching { cleanupOrphanedCiphertext() }
                .onFailure { if (it is CancellationException) throw it }
            storage.snapshotFlow().collect { snapshot -> updateCache(snapshot) }
        }
    }

    /**
     * Probes every encrypted entry. Any ciphertext whose decryption key is
     * missing is removed from disk — those entries are permanently orphaned
     * and would otherwise accumulate.
     */
    private suspend fun cleanupOrphanedCiphertext() {
        val snapshot = storage.snapshot()
        val protectionByKey = mutableMapOf<String, KSafeProtection>()

        for ((rawKey, value) in snapshot) {
            val text = (value as? StoredValue.Text)?.value ?: continue
            KeySafeMetadataManager.tryExtractCanonicalMetadataKey(rawKey)?.let { userKey ->
                KeySafeMetadataManager.parseProtection(text)?.let { protectionByKey[userKey] = it }
                return@let
            }
            KeySafeMetadataManager.tryExtractLegacyProtectionKey(rawKey)?.let { userKey ->
                if (!protectionByKey.containsKey(userKey)) {
                    KeySafeMetadataManager.parseProtection(text)?.let { protectionByKey[userKey] = it }
                }
            }
        }

        val orphanOps = mutableListOf<StorageOp>()

        for ((rawKey, value) in snapshot) {
            // Preserve legacy encrypted entries — they predate the canonical VALUE_PREFIX.
            if (rawKey.startsWith(legacyEncryptedPrefix)) continue
            if (!rawKey.startsWith(KeySafeMetadataManager.VALUE_PREFIX)) continue

            val userKey = rawKey.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
            val protection = protectionByKey[userKey] ?: continue
            val encryptedString = (value as? StoredValue.Text)?.value ?: continue

            try {
                val ciphertext = b64Decode(encryptedString)
                engine.decryptSuspend(keyAlias(userKey), ciphertext)
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
                val msg = e.message.orEmpty()
                if (msg.contains("No encryption key found", true) ||
                    msg.contains("key not found", true)
                ) {
                    orphanOps += StorageOp.Delete(rawKey)
                    orphanOps += StorageOp.Delete(metaRawKey(userKey))
                    orphanOps += StorageOp.Delete(legacyProtectionRawKey(userKey))
                    memoryCache.remove(userKey)
                    memoryCache.remove(legacyEncryptedRawKey(userKey))
                }
            }
        }

        if (orphanOps.isNotEmpty()) storage.applyBatch(orphanOps)
    }

    /**
     * Merges an on-disk snapshot into the memory cache. Dirty (in-flight) keys
     * are skipped so optimistic `putDirect` values are never clobbered by a
     * stale DataStore emission.
     */
    @PublishedApi
    internal suspend fun updateCache(snapshot: Map<String, StoredValue>) {
        val currentDirty = dirtyKeys.snapshot()
        val existingMetadata = protectionMap.snapshot()
        val validCacheKeys = mutableSetOf<String>()

        fun isDirtyForUserKey(userKey: String): Boolean {
            val canonical = valueRawKey(userKey)
            val legacyEncrypted = legacyEncryptedRawKey(userKey)
            return canonical in currentDirty || userKey in currentDirty || legacyEncrypted in currentDirty
        }

        val metadataEntries = snapshot.map { (rawKey, storedValue) ->
            rawKey to (storedValue as? StoredValue.Text)?.value
        }
        val protectionByKey = KeySafeMetadataManager.collectMetadata(
            entries = metadataEntries,
            accept = { userKey -> !isDirtyForUserKey(userKey) }
        ).toMutableMap()

        for ((rawKey, storedValue) in snapshot) {
            val classified = KeySafeMetadataManager.classifyStorageEntry(
                rawKey = rawKey,
                legacyEncryptedPrefix = legacyEncryptedPrefix,
                encryptedCacheKeyForUser = { k -> legacyEncryptedRawKey(k) },
                stagedMetadata = protectionByKey,
                existingMetadata = existingMetadata,
            ) ?: continue

            val userKey = classified.userKey
            val cacheKey = classified.cacheKey
            val explicitEncrypted = classified.encrypted

            if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKey(userKey)) {
                protectionByKey[userKey] = if (explicitEncrypted) "DEFAULT" else "NONE"
            }

            if (isDirtyForUserKey(userKey) || cacheKey in currentDirty) {
                validCacheKeys.add(cacheKey)
                continue
            }

            validCacheKeys.add(cacheKey)

            if (explicitEncrypted) {
                val encryptedString = (storedValue as? StoredValue.Text)?.value ?: continue
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED ||
                    memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE
                ) {
                    memoryCache[cacheKey] = encryptedString
                } else {
                    try {
                        val plain = engine.decryptSuspend(keyAlias(userKey), b64Decode(encryptedString))
                        memoryCache[cacheKey] = plain.decodeToString()
                    } catch (e: Throwable) {
                        if (e is CancellationException) throw e
                        /* leave out of cache */
                    }
                }
            } else {
                memoryCache[cacheKey] = storedValue.toCacheValue()
            }
        }

        validCacheKeys.addAll(currentDirty)

        // Evict cache entries that no longer exist on disk (and aren't dirty).
        for (key in memoryCache.snapshot().keys) {
            if (key !in validCacheKeys && !dirtyKeys.contains(key)) {
                memoryCache.remove(key)
            }
        }

        // Sync protectionMap: add/update entries from disk, drop entries that disappeared.
        for ((userKey, rawMeta) in protectionByKey) {
            if (!isDirtyForUserKey(userKey)) {
                protectionMap[userKey] = KeySafeMetadataManager.extractProtectionLiteral(rawMeta)
            }
        }
        for (userKey in protectionMap.snapshot().keys) {
            if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKey(userKey)) {
                protectionMap.remove(userKey)
            }
        }

        cacheInitialized.set(true)
    }

    /**
     * Detects whether a stored key is encrypted. Prefers the protection metadata
     * map; falls back to a heuristic (legacy encrypted cache-key presence) when
     * metadata is missing.
     */
    @PublishedApi
    internal fun detectProtection(key: String): KSafeProtection? {
        val meta = protectionMap[key]
        KeySafeMetadataManager.parseProtection(meta)?.let { return it }
        return if (memoryCache.containsKey(legacyEncryptedRawKey(key))) KSafeProtection.DEFAULT else null
    }

    // ============================================================
    // Write coalescer
    // ============================================================

    private fun startWriteConsumer() {
        writeScope.launch {
            val batch = mutableListOf<PendingWrite>()
            while (isActive) {
                batch.add(writeChannel.receive())
                val windowStart = TimeSource.Monotonic.markNow()
                while (batch.size < maxBatchSize) {
                    val remaining = writeCoalesceWindowMs - windowStart.elapsedNow().inWholeMilliseconds
                    if (remaining <= 0) break
                    val next = withTimeoutOrNull(remaining) { writeChannel.receive() } ?: break
                    batch.add(next)
                }
                runCatching { processBatch(batch) }
                    .onFailure { e ->
                        if (e is CancellationException) throw e
                        println("KSafe: processBatch failed, dropping ${batch.size} writes: ${e.message}")
                    }
                batch.clear()
            }
        }
    }

    private suspend fun processBatch(batch: List<PendingWrite>) {
        if (batch.isEmpty()) return

        val aliasesToDelete = mutableListOf<String>()
        val encryptedCiphertext = mutableMapOf<String, ByteArray>()

        // Encrypt in background before hitting the storage edit.
        for (op in batch) {
            if (op is PendingWrite.Encrypted) {
                val ciphertext = engine.encryptSuspend(
                    identifier = op.alias,
                    data = op.jsonString.encodeToByteArray(),
                    hardwareIsolated = op.protection == KSafeProtection.HARDWARE_ISOLATED,
                    requireUnlockedDevice = op.requireUnlockedDevice,
                )
                encryptedCiphertext[op.userKey] = ciphertext
            }
        }

        val ops = mutableListOf<StorageOp>()
        for (op in batch) {
            when (op) {
                is PendingWrite.Plain -> {
                    val key = op.userKey
                    val storedValue = if (op.value == NULL_SENTINEL) {
                        StoredValue.Text(NULL_SENTINEL)
                    } else {
                        primitiveOrTextStoredValue(op.value)
                    }
                    ops += StorageOp.Put(valueRawKey(key), storedValue)
                    ops += StorageOp.Put(metaRawKey(key), StoredValue.Text(buildMetaJson(null)))
                    // Clean up v1.6/1.7 layout.
                    ops += StorageOp.Delete(key)
                    ops += StorageOp.Delete(legacyEncryptedRawKey(key))
                    ops += StorageOp.Delete(legacyProtectionRawKey(key))
                }
                is PendingWrite.Encrypted -> {
                    val key = op.userKey
                    val ciphertext = encryptedCiphertext[key]!!
                    val base64 = b64Encode(ciphertext)
                    ops += StorageOp.Put(valueRawKey(key), StoredValue.Text(base64))
                    ops += StorageOp.Put(
                        metaRawKey(key),
                        StoredValue.Text(buildMetaJson(op.protection, op.requireUnlockedDevice))
                    )
                    ops += StorageOp.Delete(key)
                    ops += StorageOp.Delete(legacyEncryptedRawKey(key))
                    ops += StorageOp.Delete(legacyProtectionRawKey(key))
                }
                is PendingWrite.Delete -> {
                    val key = op.userKey
                    ops += StorageOp.Delete(valueRawKey(key))
                    ops += StorageOp.Delete(key)
                    ops += StorageOp.Delete(metaRawKey(key))
                    ops += StorageOp.Delete(legacyEncryptedRawKey(key))
                    ops += StorageOp.Delete(legacyProtectionRawKey(key))
                    aliasesToDelete += keyAlias(key)
                }
            }
        }

        storage.applyBatch(ops)

        for (alias in aliasesToDelete) engine.deleteKeySuspend(alias)

        // For ENCRYPTED memory policy: swap plaintext → ciphertext in cache.
        // CAS guard prevents overwriting a newer `putDirect` issued mid-batch.
        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED ||
            memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE
        ) {
            for (op in batch) {
                if (op is PendingWrite.Encrypted) {
                    val base64 = b64Encode(encryptedCiphertext[op.userKey]!!)
                    memoryCache.replaceIf(op.rawCacheKey, op.jsonString, base64)
                }
            }
        }
        // Dirty flags deliberately NOT cleared — see the long note in the original
        // JVM implementation for why (prevents stale collector snapshots from
        // clobbering optimistic writes).
    }

    // ============================================================
    // Raw read/write API (all inline wrappers in KSafe delegate here)
    // ============================================================

    @PublishedApi
    internal fun getDirectRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        ensureCacheReadyBlocking()
        val detected = detectProtection(key)
        return resolveFromCache(key, defaultValue, detected, serializer)
    }

    @PublishedApi
    internal suspend fun getRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        ensureCacheReadySuspend()
        val detected = detectProtection(key)
        return withContext(Dispatchers.Default) {
            resolveFromCache(key, defaultValue, detected, serializer)
        }
    }

    @PublishedApi
    internal fun getFlowRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Flow<Any?> {
        return storage.snapshotFlow().map { snapshot ->
            val metaRaw = (snapshot[metaRawKey(key)] as? StoredValue.Text)?.value
                ?: (snapshot[legacyProtectionRawKey(key)] as? StoredValue.Text)?.value
            val protection = KeySafeMetadataManager.parseProtection(metaRaw)
                ?: if (snapshot[legacyEncryptedRawKey(key)] != null) KSafeProtection.DEFAULT else null

            when (protection) {
                null -> {
                    val plain = snapshot[valueRawKey(key)] ?: snapshot[key]
                    if (plain != null) convertStoredValue(plain.toCacheValue(), defaultValue, serializer)
                    else defaultValue
                }
                else -> {
                    val enc = (snapshot[valueRawKey(key)] as? StoredValue.Text)?.value
                        ?: (snapshot[legacyEncryptedRawKey(key)] as? StoredValue.Text)?.value
                    if (enc != null) {
                        try {
                            val plainBytes = engine.decryptSuspend(keyAlias(key), b64Decode(enc))
                            val rawString = plainBytes.decodeToString()
                            if (rawString == NULL_SENTINEL) null
                            else jsonDecode(json, serializer, rawString)
                        } catch (e: Throwable) {
                            if (e is CancellationException) throw e
                            if (isTransientDecryptFailure(e)) throw e
                            defaultValue
                        }
                    } else defaultValue
                }
            }
        }.distinctUntilChanged()
    }

    @PublishedApi
    internal fun putDirectRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) {
        @Suppress("NAME_SHADOWING") val mode = modeTransformer(mode)
        val protection = mode.toProtection()
        val requireUnlockedDevice = mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice

        if (protection != null) {
            val rawCacheKey = legacyEncryptedRawKey(key)
            dirtyKeys.add(rawCacheKey)

            val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
            memoryCache[rawCacheKey] = jsonString
            protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(protection)

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                plaintextCache[rawCacheKey] = CachedPlaintext(
                    jsonString, TimeSource.Monotonic.markNow() + plaintextCacheTtl
                )
            }

            writeChannel.trySend(
                PendingWrite.Encrypted(
                    userKey = key,
                    rawCacheKey = rawCacheKey,
                    jsonString = jsonString,
                    alias = keyAlias(key),
                    protection = protection,
                    requireUnlockedDevice = requireUnlockedDevice,
                )
            )
        } else {
            val rawCacheKey = key
            dirtyKeys.add(rawCacheKey)

            val toCache: Any = if (value == null) NULL_SENTINEL
            else when (value) {
                is Boolean, is Int, is Long, is Float, is Double, is String -> value
                else -> jsonEncode(json, serializer, value)
            }
            memoryCache[rawCacheKey] = toCache
            protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(null)

            val storedInBatch: Any = if (value == null) NULL_SENTINEL
            else when (value) {
                is Boolean, is Int, is Long, is Float, is Double, is String -> value
                else -> jsonEncode(json, serializer, value)
            }
            writeChannel.trySend(PendingWrite.Plain(userKey = key, rawCacheKey = rawCacheKey, value = storedInBatch))
        }
    }

    @PublishedApi
    internal suspend fun putRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) {
        @Suppress("NAME_SHADOWING") val mode = modeTransformer(mode)
        if (mode is KSafeWriteMode.Encrypted) {
            putEncryptedSuspend(key, value, mode.toProtection()!!, mode.requireUnlockedDevice, serializer)
        } else {
            putPlainSuspend(key, value, serializer)
        }
    }

    private suspend fun putEncryptedSuspend(
        key: String,
        value: Any?,
        protection: KSafeProtection,
        requireUnlockedDevice: Boolean,
        serializer: KSerializer<*>,
    ) {
        val rawCacheKey = legacyEncryptedRawKey(key)
        dirtyKeys.add(rawCacheKey)
        protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(protection)

        val rawString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
        val encryptedBytes = withContext(Dispatchers.Default) {
            engine.encryptSuspend(
                identifier = keyAlias(key),
                data = rawString.encodeToByteArray(),
                hardwareIsolated = protection == KSafeProtection.HARDWARE_ISOLATED,
                requireUnlockedDevice = requireUnlockedDevice,
            )
        }
        val encryptedString = b64Encode(encryptedBytes)

        storage.applyBatch(listOf(
            StorageOp.Put(valueRawKey(key), StoredValue.Text(encryptedString)),
            StorageOp.Put(metaRawKey(key), StoredValue.Text(buildMetaJson(protection, requireUnlockedDevice))),
            StorageOp.Delete(key),
            StorageOp.Delete(legacyEncryptedRawKey(key)),
            StorageOp.Delete(legacyProtectionRawKey(key)),
        ))

        val cacheValue = if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED ||
            memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE
        ) encryptedString else rawString
        memoryCache[rawCacheKey] = cacheValue

        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
            plaintextCache[rawCacheKey] = CachedPlaintext(
                rawString, TimeSource.Monotonic.markNow() + plaintextCacheTtl
            )
        }
    }

    private suspend fun putPlainSuspend(key: String, value: Any?, serializer: KSerializer<*>) {
        dirtyKeys.add(key)
        protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(null)

        val storedValue: StoredValue = if (value == null) {
            StoredValue.Text(NULL_SENTINEL)
        } else when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> primitiveToStoredValue(value)
            else -> StoredValue.Text(jsonEncode(json, serializer, value))
        }
        storage.applyBatch(listOf(
            StorageOp.Put(valueRawKey(key), storedValue),
            StorageOp.Put(metaRawKey(key), StoredValue.Text(buildMetaJson(null))),
            StorageOp.Delete(key),
            StorageOp.Delete(legacyEncryptedRawKey(key)),
            StorageOp.Delete(legacyProtectionRawKey(key)),
        ))

        memoryCache[key] = if (value == null) NULL_SENTINEL else storedValue.toCacheValue()
    }

    fun deleteDirect(key: String) {
        val rawKey = key
        val encKeyName = legacyEncryptedRawKey(key)
        dirtyKeys.add(rawKey)
        dirtyKeys.add(encKeyName)
        memoryCache.remove(rawKey)
        memoryCache.remove(encKeyName)
        plaintextCache.remove(rawKey)
        plaintextCache.remove(encKeyName)
        protectionMap.remove(key)
        writeChannel.trySend(PendingWrite.Delete(userKey = key, rawCacheKey = rawKey))
    }

    suspend fun delete(key: String) {
        storage.applyBatch(listOf(
            StorageOp.Delete(valueRawKey(key)),
            StorageOp.Delete(key),
            StorageOp.Delete(metaRawKey(key)),
            StorageOp.Delete(legacyEncryptedRawKey(key)),
            StorageOp.Delete(legacyProtectionRawKey(key)),
        ))
        engine.deleteKeySuspend(keyAlias(key))
        memoryCache.remove(key)
        memoryCache.remove(legacyEncryptedRawKey(key))
        plaintextCache.remove(key)
        plaintextCache.remove(legacyEncryptedRawKey(key))
        protectionMap.remove(key)
    }

    suspend fun clearAll() {
        storage.clear()
        memoryCache.clear()
        plaintextCache.clear()
        protectionMap.clear()
    }

    fun getKeyInfo(key: String): KSafeKeyInfo? {
        ensureCacheReadyBlocking()
        val hasEncrypted = memoryCache.containsKey(legacyEncryptedRawKey(key))
        val hasPlain = memoryCache.containsKey(key)
        if (!hasEncrypted && !hasPlain) return null
        val protection = KeySafeMetadataManager.parseProtection(protectionMap[key])
            ?: if (hasEncrypted) KSafeProtection.DEFAULT else null
        return KSafeKeyInfo(protection, resolveKeyStorage(key, protection))
    }

    // ============================================================
    // Cache resolution — identical semantics to the original resolveFromCacheRaw
    // ============================================================

    private fun resolveFromCache(
        key: String,
        defaultValue: Any?,
        protection: KSafeProtection?,
        serializer: KSerializer<*>,
    ): Any? {
        val cacheKey = if (protection != null) legacyEncryptedRawKey(key) else key
        val cachedValue = memoryCache[cacheKey] ?: return defaultValue

        return if (protection != null) {
            var jsonString: String? = null
            var deserialized: Any? = null
            var success = false

            if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED ||
                memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE
            ) {
                if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                    val cached = plaintextCache[cacheKey]
                    if (cached != null && TimeSource.Monotonic.markNow() < cached.expiresAt) {
                        if (cached.value == NULL_SENTINEL) return null
                        try {
                            return jsonDecode(json, serializer, cached.value)
                        } catch (e: Throwable) {
                            if (e is CancellationException) throw e
                            /* fall through */
                        }
                    }
                }

                try {
                    val encryptedString = cachedValue as? String
                    if (encryptedString != null) {
                        val plainBytes = engine.decrypt(keyAlias(key), b64Decode(encryptedString))
                        val candidate = plainBytes.decodeToString()
                        deserialized = if (candidate == NULL_SENTINEL) null
                        else jsonDecode(json, serializer, candidate)
                        success = true
                        if (memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE) {
                            plaintextCache[cacheKey] = CachedPlaintext(
                                candidate, TimeSource.Monotonic.markNow() + plaintextCacheTtl
                            )
                        }
                    }
                } catch (e: Throwable) {
                    if (e is CancellationException) throw e
                    // Transient keystore failures (locked device, hardware busy) must
                    // propagate so callers can retry instead of getting silent defaults.
                    if (isTransientDecryptFailure(e)) throw e
                    /* else fall through to plain-text fallback */
                }
            } else {
                jsonString = cachedValue as? String
            }

            if (success) return deserialized
            if (jsonString == null) jsonString = cachedValue as? String
            if (jsonString == null) return defaultValue
            if (jsonString == NULL_SENTINEL) return null
            try {
                jsonDecode(json, serializer, jsonString)
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
                defaultValue
            }
        } else {
            if (isNullSentinel(cachedValue)) return null
            convertStoredValue(cachedValue, defaultValue, serializer)
        }
    }

    private fun convertStoredValue(storedValue: Any?, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        if (storedValue == null) return defaultValue
        if (isNullSentinel(storedValue)) return null

        // We dispatch on the serializer's primitive kind rather than on
        // `defaultValue`'s runtime class — it survives a null default (e.g.
        // `get<Int?>("k", null)`) and it's JS-safe (on Kotlin/JS `0f is Int`
        // is `true` because `0f` is represented as the integer `0`). Each
        // branch handles both typed-stored primitives (DataStore) and
        // string-stored primitives (web localStorage).
        return when (primitiveKindOrNull(serializer)) {
            kotlinx.serialization.descriptors.PrimitiveKind.BOOLEAN -> when (storedValue) {
                is Boolean -> storedValue
                is String -> storedValue.toBooleanStrictOrNull() ?: defaultValue
                else -> defaultValue
            }
            kotlinx.serialization.descriptors.PrimitiveKind.INT -> when (storedValue) {
                is Int -> storedValue
                is Long -> if (storedValue in Int.MIN_VALUE..Int.MAX_VALUE) storedValue.toInt() else defaultValue
                is String -> storedValue.toIntOrNull() ?: defaultValue
                else -> defaultValue
            }
            kotlinx.serialization.descriptors.PrimitiveKind.LONG -> when (storedValue) {
                is Long -> storedValue
                is Int -> storedValue.toLong()
                is String -> storedValue.toLongOrNull() ?: defaultValue
                else -> defaultValue
            }
            kotlinx.serialization.descriptors.PrimitiveKind.FLOAT -> when (storedValue) {
                is Float -> storedValue
                is String -> storedValue.toFloatOrNull() ?: defaultValue
                else -> defaultValue
            }
            kotlinx.serialization.descriptors.PrimitiveKind.DOUBLE -> when (storedValue) {
                is Double -> storedValue
                is String -> storedValue.toDoubleOrNull() ?: defaultValue
                else -> defaultValue
            }
            kotlinx.serialization.descriptors.PrimitiveKind.STRING -> when (storedValue) {
                is String -> if (storedValue == NULL_SENTINEL) null else storedValue
                else -> defaultValue
            }
            else -> {
                // Complex `@Serializable` type — expect a JSON string.
                if (storedValue !is String) return storedValue
                if (storedValue == NULL_SENTINEL) return null
                try {
                    jsonDecode(json, serializer, storedValue)
                } catch (e: Throwable) {
                    if (e is CancellationException) throw e
                    defaultValue
                }
            }
        }
    }

    private fun primitiveOrTextStoredValue(value: Any): StoredValue = when (value) {
        is Boolean -> StoredValue.BoolVal(value)
        is Int -> StoredValue.IntVal(value)
        is Long -> StoredValue.LongVal(value)
        is Float -> StoredValue.FloatVal(value)
        is Double -> StoredValue.DoubleVal(value)
        is String -> StoredValue.Text(value)
        else -> error("primitiveOrTextStoredValue: unsupported type ${value::class}")
    }

    // ============================================================
    // Cache-readiness helpers
    // ============================================================

    private fun ensureCacheReadyBlocking() {
        if (cacheInitialized.get()) return
        // Best-effort cold-start freshness. Android/iOS/JVM will block once to
        // populate the cache; web can't block so the call throws and we fall
        // through — a concurrent `getDirect` there returns its default until
        // the background preload completes, which matches pre-refactor web
        // behaviour.
        try {
            runBlockingOnPlatform {
                if (!cacheInitialized.get()) updateCache(storage.snapshot())
            }
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
            /* web: no blocking available */
        }
    }

    suspend fun ensureCacheReadySuspend() {
        if (cacheInitialized.get()) return
        updateCache(storage.snapshot())
    }

    /**
     * Releases the long-running infrastructure this core owns: cancels both
     * background scopes (write consumer + snapshot collector) and closes the
     * write channel. Idempotent — safe to call multiple times. After cancel
     * the instance can no longer process puts/reads; further calls behave
     * as no-ops on the now-cancelled scopes.
     *
     * Production callers usually never need this — a singleton that lives
     * for the process lifetime is the dominant usage and the OS reclaims
     * everything on exit. The case that matters is **test suites** and any
     * code that re-creates `KSafe` mid-process: without `cancel()` each
     * abandoned instance is pinned in heap by its suspended coroutines
     * (held as GC roots by `Dispatchers.Default`), and the live-set grows
     * unboundedly across the run.
     */
    internal fun cancel() {
        // Cancel the scopes only — do NOT close `writeChannel`. Closing the
        // channel makes the consumer's pending `writeChannel.receive()`
        // throw `ClosedReceiveChannelException`, which is *not* a
        // CancellationException and therefore bubbles up to the scope's
        // default uncaught-exception handler. Under kotlinx-coroutines-test
        // that surfaces in the next test as `UncaughtExceptionsBeforeTest`.
        // Cancelling the scope already terminates the consumer (its receive
        // call resumes with CancellationException, which is normal and
        // silenced); the channel is then reachable only via the cancelled
        // scope and is GC'd along with the rest of the core.
        writeScope.cancel()
        collectorScope.cancel()
        // Platform hook — cancels the DataStore scope on JVM/Android/iOS
        // and evicts the Android process-static DataStore cache entry.
        // Without this, DataStore's internal coroutines stay alive on
        // `Dispatchers.IO` and pin the entire DataStore graph (file
        // handle, MutableStateFlow, cached Preferences) in heap forever.
        runCatching { onCancel() }
    }

    private fun isTransientDecryptFailure(e: Throwable): Boolean {
        val msg = e.message ?: return false
        // Android Keystore (device locked, Keystore process crashed) and iOS
        // Keychain (Secure Enclave busy) both surface through message strings
        // we can recognise. JVM software encryption never produces these —
        // there it's a no-op.
        return msg.contains("device is locked", ignoreCase = true) ||
            msg.contains("Keystore", ignoreCase = true)
    }

    companion object {
        /**
         * Marker stored on disk when the caller persisted a `null`. Lets us tell
         * "key not present" apart from "key present with null value".
         */
        @PublishedApi
        internal const val NULL_SENTINEL: String = "__KSAFE_NULL_VALUE__"

        @PublishedApi
        internal fun isNullSentinel(value: Any?): Boolean = value == NULL_SENTINEL
    }
}

@OptIn(ExperimentalEncodingApi::class)
private fun b64Encode(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
private fun b64Decode(encoded: String): ByteArray = Base64.decode(encoded)
