package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.KSafeKeyInfo
import eu.anifantakis.lib.ksafe.KSafeKeyStorage
import eu.anifantakis.lib.ksafe.KSafeMemoryPolicy
import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.KSafeProtectionLevel
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import eu.anifantakis.lib.ksafe.toProtection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.ComparableTimeMark
import kotlin.time.Duration
import kotlin.time.TimeSource

/**
 * Platform-independent orchestration engine between the public [KSafe] API and the
 * platform backends ([KSafePlatformStorage], [KSafeEncryption]). Owns the hot cache,
 * write coalescer, protection metadata, background preload, and orphan cleanup.
 */
@PublishedApi
internal class KSafeCore(
    @PublishedApi internal val storage: KSafePlatformStorage,
    /** Deferred so the platform shell can swap in a test engine after wiring. */
    engineProvider: () -> KSafeEncryption,
    private val config: KSafeConfig,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy,
    @PublishedApi internal val plaintextCacheTtl: Duration,
    /** Storage tier reported by `getKeyInfo`; platform shells inspect StrongBox / Secure Enclave. */
    private val resolveKeyStorage: (userKey: String, protection: KSafeProtection?) -> KSafeKeyStorage,
    /** Per-key [KSafeProtectionLevel] reported by `getKeyInfo`; platform-specific. */
    private val resolveKeyLevel: (userKey: String, protection: KSafeProtection?) -> KSafeProtectionLevel,
    /** Per-platform migration hook run once before orphan cleanup (iOS accessibility tiers). */
    private val migrateAccessPolicy: suspend (isUserKeyDirty: (String) -> Boolean) -> Unit = {},
    private val lazyLoad: Boolean = false,
    /** Builds the per-entry Keystore/Keychain alias for a user key. */
    @PublishedApi internal val keyAlias: (userKey: String) -> String,
    /**
     * Master alias for the datastore, one per unlock policy (relaxed/strict). Holds the
     * AES key shared by v2 DEFAULT entries; HARDWARE_ISOLATED entries use per-entry keys.
     */
    @PublishedApi internal val masterAlias: (requireUnlockedDevice: Boolean) -> String,
    /** Prefix recognising legacy-format encrypted entries on disk (iOS overrides per filename). */
    private val legacyEncryptedPrefix: String = KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX,
    /** Legacy-format encrypted raw key for a user key (iOS overrides per filename). */
    private val legacyEncryptedKeyFor: (userKey: String) -> String =
        KeySafeMetadataManager::legacyEncryptedRawKey,
    /** Pre-write mode transform (Android/iOS promote deprecated StrongBox/Secure Enclave flags). */
    private val modeTransformer: (KSafeWriteMode) -> KSafeWriteMode = { it },
    /** Platform cleanup invoked from [cancel]; DataStore-backed platforms cancel their scope here. */
    private val onCancel: () -> Unit = {},
) {

    @PublishedApi internal val engine: KSafeEncryption by lazy(engineProvider)

    @PublishedApi internal val json: Json = config.json

    @PublishedApi
    internal val memoryCache = KSafeConcurrentMap<Any>()

    /** Protection literal per user key ("NONE", "DEFAULT", "HARDWARE_ISOLATED"). */
    @PublishedApi
    internal val protectionMap = KSafeConcurrentMap<String>()

    /**
     * Per-encrypted-key envelope info; tells the read path which alias decrypts the entry
     * (v2 + DEFAULT routes to the master alias picked by `requireUnlockedDevice`).
     * Plain entries are never present.
     */
    @PublishedApi
    internal data class EncMeta(val envelopeVersion: Int, val requireUnlockedDevice: Boolean)

    @PublishedApi
    internal val encMetaMap = KSafeConcurrentMap<EncMeta>()

    @PublishedApi
    internal class CachedPlaintext(val value: String, val expiresAt: ComparableTimeMark)

    @PublishedApi
    internal val plaintextCache = KSafeConcurrentMap<CachedPlaintext>()

    /**
     * Latest write's identity token per user key, claimed before any optimistic mutation.
     * A failed write may only roll back state it still owns — never state a newer
     * in-flight write to the same key has since claimed. Not wiped by clearAll.
     */
    private val writeOwners = KSafeConcurrentMap<Any>()

    /** Test-only seam invoked inside the post-commit repair; always `null` in production. */
    @PublishedApi
    internal var postCommitRepairHook: ((String) -> Unit)? = null

    /** `true` when the primary [memoryCache] holds Base64 ciphertext at rest. */
    private val cacheHoldsCiphertext: Boolean =
        memoryPolicy == KSafeMemoryPolicy.ENCRYPTED ||
            memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE ||
            memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT

    /** `true` for policies with the secondary [plaintextCache] (TTL-bounded or permanent). */
    private val usesPlaintextSideCache: Boolean =
        memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE ||
            memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT

    /** Side-cache freshness: never expires under LAZY_PLAIN_TEXT, TTL-bounded otherwise. */
    private fun plaintextStillValid(cached: CachedPlaintext): Boolean =
        memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT ||
            TimeSource.Monotonic.markNow() < cached.expiresAt

    private fun plaintextExpiry(): ComparableTimeMark =
        if (memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT) TimeSource.Monotonic.markNow()
        else TimeSource.Monotonic.markNow() + plaintextCacheTtl

    @PublishedApi
    internal val cacheInitialized = KSafeAtomicFlag(false)

    /**
     * Set once an encrypted entry is ever seen; lets plaintext-only reads skip
     * [detectProtection]'s map lookups. Monotonic — never reset.
     */
    @PublishedApi
    internal val hasAnyEncryptedKey = KSafeAtomicFlag(false)

    /**
     * Raw cache keys with in-flight writes, in both canonical and legacy encrypted forms,
     * so the background collector never stomps on an optimistic update.
     */
    @PublishedApi
    internal val dirtyKeys = KSafeConcurrentSet<String>()

    private val writeScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val collectorScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    /** Logical write queue — encryption happens inside the consumer, not on UI. */
    private val writeChannel = Channel<PendingWrite>(Channel.UNLIMITED)

    private val writeCoalesceWindowMs = 16L   // ~1 frame at 60 fps
    private val maxBatchSize = 200

    /**
     * Caps concurrent encrypt/decrypt calls: overlapping keystore IPC pipelines well,
     * but unbounded fan-out floods Binder / Keychain and over-subscribes the dispatcher.
     */
    private val maxParallelEncrypts = 8

    init {
        startWriteConsumer()
        if (!lazyLoad) startBackgroundCollector()
        prewarmMasterKeys()
    }

    /**
     * Eagerly creates both master keys (relaxed + strict) off-thread. Failures are
     * swallowed — the lazy-create path retries on the first real write.
     */
    private fun prewarmMasterKeys() {
        writeScope.launch {
            for (requireUnlocked in listOf(false, true)) {
                try {
                    engine.prewarmKey(
                        identifier = masterAlias(requireUnlocked),
                        hardwareIsolated = false,
                        requireUnlockedDevice = requireUnlocked,
                    )
                } catch (e: Throwable) {
                    if (e is CancellationException) throw e
                    /* swallow — lazy path will retry on first real write */
                }
            }
            // Read-only warm of an already-persisted relaxed DEK so the first encrypted
            // read doesn't block the caller thread on storage I/O; never creates a DEK.
            try {
                engine.prewarmDekReadIfPresent(masterAlias(false), requireUnlockedDevice = false)
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
                /* swallow — the lazy read path warms the cache on first use */
            }
        }
    }

    private sealed class PendingWrite {
        abstract val userKey: String
        abstract val rawCacheKey: String

        /** Non-null when a caller awaits the disk commit; completed (or failed) after applyBatch. */
        abstract val completion: CompletableDeferred<Unit>?

        /**
         * Identity token claimed in [writeOwners] before the issuing call's optimistic
         * mutations; a failed write may roll back only while it is still the key's latest
         * writer. Required (no default) so call sites can't enqueue an unregistered token.
         */
        abstract val writeToken: Any

        data class Plain(
            override val userKey: String,
            override val rawCacheKey: String,
            /** A primitive, the null sentinel, or pre-encoded JSON for complex types. */
            val value: Any,
            override val writeToken: Any,
            override val completion: CompletableDeferred<Unit>? = null,
        ) : PendingWrite()

        data class Encrypted(
            override val userKey: String,
            override val rawCacheKey: String,
            val jsonString: String,
            val protection: KSafeProtection,
            val requireUnlockedDevice: Boolean,
            override val writeToken: Any,
            override val completion: CompletableDeferred<Unit>? = null,
        ) : PendingWrite()

        data class Delete(
            override val userKey: String,
            override val rawCacheKey: String,
            override val writeToken: Any,
            override val completion: CompletableDeferred<Unit>? = null,
        ) : PendingWrite()

        /**
         * Routes [clearAll] through the write channel so the wipe is FIFO-serialized with
         * concurrent writes; handled as a batch boundary in [processBatchBody].
         */
        data class ClearAll(
            override val completion: CompletableDeferred<Unit>? = null,
        ) : PendingWrite() {
            override val userKey: String get() = "__ksafe_clear_all__"
            override val rawCacheKey: String get() = "__ksafe_clear_all__"
            override val writeToken: Any get() = this // never rolled back per-key
        }
    }

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

    /**
     * Write alias: DEFAULT routes to the master alias for the unlock policy;
     * HARDWARE_ISOLATED always uses the per-entry alias.
     */
    @PublishedApi
    internal fun aliasForWrite(
        userKey: String,
        protection: KSafeProtection,
        requireUnlockedDevice: Boolean,
    ): String {
        if (protection == KSafeProtection.DEFAULT) return masterAlias(requireUnlockedDevice)
        return keyAlias(userKey)
    }

    /**
     * Read alias from the entry's recorded envelope in [encMetaMap]: v2 + DEFAULT routes to
     * the master alias; v1, plain, or HARDWARE_ISOLATED uses the per-entry alias — also the
     * safe default when no metadata is loaded yet.
     */
    @PublishedApi
    internal fun aliasForRead(userKey: String, protection: KSafeProtection?): String {
        val em = encMetaMap[userKey]
        if (em != null && em.envelopeVersion >= KeySafeMetadataManager.ENVELOPE_VERSION_V2 &&
            protection == KSafeProtection.DEFAULT
        ) {
            return masterAlias(em.requireUnlockedDevice)
        }
        return keyAlias(userKey)
    }

    private fun startBackgroundCollector() {
        collectorScope.launch {
            // Startup cleanup runs only AFTER the first snapshot emission: sweeping against
            // an empty pre-migration snapshot would treat every Keychain key as orphaned and
            // delete unrecreatable Secure Enclave keys.
            var firstEmission = true
            storage.snapshotFlow().collect { snapshot ->
                updateCache(snapshot)
                if (firstEmission) {
                    firstEmission = false
                    runOneTimeStartupCleanup()
                }
            }
        }
    }

    /** Guards the one-time startup cleanup (collector first emission or lazy first access). */
    private val startupCleanupDone = KSafeAtomicFlag(false)
    private val lazyStartupCleanupLaunched = KSafeAtomicFlag(false)

    /**
     * One-time post-first-load cleanup: access-policy migration, orphan-ciphertext sweep,
     * and legacy key-material migration. Best-effort and idempotent; must run only after
     * the first snapshot has populated the cache.
     */
    private suspend fun runOneTimeStartupCleanup() {
        if (!startupCleanupDone.compareAndSet(false, true)) return
        runCatching { migrateAccessPolicy(::isUserKeyDirty) }
            .onFailure { if (it is CancellationException) throw it }
        runCatching { cleanupOrphanedCiphertext() }
            .onFailure { if (it is CancellationException) throw it }
        runCatching { engine.migrateLegacyKeysSuspend() }
            .onFailure { if (it is CancellationException) throw it }
    }

    /**
     * Under [lazyLoad] no collector runs, so the startup cleanup is triggered once by the
     * first access — on the background scope so it never blocks the read.
     */
    private fun triggerLazyStartupCleanupOnce() {
        if (!lazyLoad || startupCleanupDone.get()) return
        if (!lazyStartupCleanupLaunched.compareAndSet(false, true)) return
        collectorScope.launch { runOneTimeStartupCleanup() }
    }

    /** Removes ciphertext whose decryption key is missing — permanently orphaned entries. */
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

        // Candidates are collected first so the decrypt probes run concurrently,
        // semaphore-capped keystore IPC.
        data class Candidate(
            val rawKey: String,
            val userKey: String,
            val ciphertextB64: String,
            val protection: KSafeProtection,
        )

        val candidates = snapshot.mapNotNull { (rawKey, value) ->
            // Preserve legacy encrypted entries — they predate the canonical VALUE_PREFIX.
            if (rawKey.startsWith(legacyEncryptedPrefix)) return@mapNotNull null
            if (!rawKey.startsWith(KeySafeMetadataManager.VALUE_PREFIX)) return@mapNotNull null
            val userKey = rawKey.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
            val protection = protectionByKey[userKey] ?: return@mapNotNull null
            val encryptedString = (value as? StoredValue.Text)?.value ?: return@mapNotNull null
            Candidate(rawKey, userKey, encryptedString, protection)
        }

        if (candidates.isEmpty()) return

        val gate = Semaphore(maxParallelEncrypts)
        val orphans = coroutineScope {
            candidates.map { c ->
                async {
                    gate.withPermit {
                        try {
                            // Probe with the recorded unlock policy: a locked-device probe throws
                            // a transient error, not "key not found", so strict entries are never
                            // misclassified as orphans.
                            val reqUnlocked = encMetaMap[c.userKey]?.requireUnlockedDevice == true
                            engine.decryptSuspend(aliasForRead(c.userKey, c.protection), b64Decode(c.ciphertextB64), reqUnlocked)
                            null
                        } catch (e: Throwable) {
                            if (e is CancellationException) throw e
                            val msg = e.message.orEmpty()
                            if (msg.contains("No encryption key found", true) ||
                                msg.contains("key not found", true)
                            ) c else null
                        }
                    }
                }
            }.awaitAll().filterNotNull()
        }

        if (orphans.isEmpty()) return

        val orphanOps = mutableListOf<StorageOp>()
        for (c in orphans) {
            // Live re-check: a write racing the sweep marks the key dirty before committing;
            // deleting its ciphertext here would silently revert an acknowledged write.
            if (isUserKeyDirty(c.userKey)) continue
            orphanOps += StorageOp.Delete(c.rawKey)
            orphanOps += StorageOp.Delete(metaRawKey(c.userKey))
            orphanOps += StorageOp.Delete(legacyProtectionRawKey(c.userKey))
            memoryCache.remove(c.userKey)
            memoryCache.remove(legacyEncryptedRawKey(c.userKey))
        }
        if (orphanOps.isEmpty()) return
        storage.applyBatch(orphanOps)
    }

    /** True if [userKey] has an in-flight write under any raw-key form; reads the LIVE set. */
    private fun isUserKeyDirty(userKey: String): Boolean =
        dirtyKeys.contains(valueRawKey(userKey)) ||
            dirtyKeys.contains(legacyEncryptedRawKey(userKey)) ||
            dirtyKeys.contains(userKey)

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

        // Frozen + LIVE dirty check for the shared metadata maps: a write landing after the
        // snapshot must not have its metadata reverted to stale disk state, while a key
        // rolled back mid-merge still defers to the rollback's own fresher re-merge.
        fun isDirtyForUserKeyLive(userKey: String): Boolean =
            isDirtyForUserKey(userKey) || isUserKeyDirty(userKey)

        val metadataEntries = snapshot.map { (rawKey, storedValue) ->
            rawKey to (storedValue as? StoredValue.Text)?.value
        }
        val protectionByKey = KeySafeMetadataManager.collectMetadata(
            entries = metadataEntries,
            accept = { userKey -> !isDirtyForUserKey(userKey) }
        ).toMutableMap()

        // encMetaMap is populated BEFORE the decrypt pass — aliasForRead consults it.
        for ((userKey, rawMeta) in protectionByKey) {
            if (isDirtyForUserKeyLive(userKey)) continue
            // Skip plain entries — encMetaMap only tracks encrypted ones.
            if (KeySafeMetadataManager.parseProtection(rawMeta) == null) continue
            val env = KeySafeMetadataManager.parseEnvelopeVersion(rawMeta)
            val unlocked = KeySafeMetadataManager.parseRequireUnlockedDevice(rawMeta)
            encMetaMap[userKey] = EncMeta(envelopeVersion = env, requireUnlockedDevice = unlocked)
        }

        // PLAIN_TEXT-memory decrypts are deferred to a concurrent second pass —
        // serialised keystore IPC dominates cold-start time on large stores.
        data class PendingDecrypt(
            val userKey: String,
            val cacheKey: String,
            val ciphertextB64: String,
            val protection: KSafeProtection,
        )
        val pendingDecrypts = mutableListOf<PendingDecrypt>()

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
                hasAnyEncryptedKey.set(true)
                val encryptedString = (storedValue as? StoredValue.Text)?.value ?: continue
                // Strict (requireUnlockedDevice) entries stay ciphertext even under a
                // plaintext policy so every read hits the native store and enforces the lock.
                val strict = encMetaMap[userKey]?.requireUnlockedDevice == true
                if (cacheHoldsCiphertext || strict) {
                    // Live re-check: a write landing after the snapshot must not be
                    // clobbered with the older disk value.
                    if (!isUserKeyDirty(userKey)) {
                        val previousCiphertext = memoryCache[cacheKey]
                        memoryCache[cacheKey] = encryptedString
                        // A changed ciphertext means an external write (fresh IV per encrypt) —
                        // evict the stale side-cache entry, which under LAZY_PLAIN_TEXT would
                        // otherwise serve the old plaintext forever.
                        if (usesPlaintextSideCache && previousCiphertext != encryptedString) {
                            plaintextCache.remove(cacheKey)
                        }
                    }
                } else {
                    val protection = KeySafeMetadataManager.parseProtection(protectionByKey[userKey])
                        ?: KSafeProtection.DEFAULT
                    pendingDecrypts += PendingDecrypt(userKey, cacheKey, encryptedString, protection)
                }
            } else {
                if (!isUserKeyDirty(userKey)) memoryCache[cacheKey] = storedValue.toCacheValue()
            }
        }

        // Second pass: concurrent decrypts; failures are dropped from the cache.
        if (pendingDecrypts.isNotEmpty()) {
            val gate = Semaphore(maxParallelEncrypts)
            coroutineScope {
                pendingDecrypts.map { p ->
                    async {
                        gate.withPermit {
                            try {
                                val alias = aliasForRead(p.userKey, p.protection)
                                // Strict entries are excluded upstream; the flag is passed
                                // defensively so any that slip through still enforce the lock.
                                val reqUnlocked = encMetaMap[p.userKey]?.requireUnlockedDevice == true
                                val plain = engine.decryptSuspend(alias, b64Decode(p.ciphertextB64), reqUnlocked)
                                // Live re-check after the slow decrypt: don't overwrite a write
                                // that landed during the round-trip with this stale disk value.
                                if (!isUserKeyDirty(p.userKey)) memoryCache[p.cacheKey] = plain.decodeToString()
                            } catch (e: Throwable) {
                                if (e is CancellationException) throw e
                                /* leave out of cache */
                            }
                        }
                    }
                }.awaitAll()
            }
        }

        validCacheKeys.addAll(currentDirty)

        // Evict cache entries that no longer exist on disk (and aren't dirty).
        for (key in memoryCache.snapshot().keys) {
            if (key !in validCacheKeys && !dirtyKeys.contains(key)) {
                memoryCache.remove(key)
                // Mirror into the side cache — an externally deleted key's plaintext would
                // otherwise be served forever under never-expiring LAZY_PLAIN_TEXT.
                if (usesPlaintextSideCache) plaintextCache.remove(key)
            }
        }

        // Sync protectionMap from disk; live-checked so a put that changed this key's
        // protection mid-merge keeps its fresh routing metadata.
        for ((userKey, rawMeta) in protectionByKey) {
            if (!isDirtyForUserKeyLive(userKey)) {
                protectionMap[userKey] = KeySafeMetadataManager.extractProtectionLiteral(rawMeta)
            }
        }
        for (userKey in protectionMap.snapshot().keys) {
            if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKeyLive(userKey)) {
                protectionMap.remove(userKey)
            }
        }

        // Drop encMetaMap entries with no on-disk metadata (live-checked, as above).
        for (userKey in encMetaMap.snapshot().keys) {
            if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKeyLive(userKey)) {
                encMetaMap.remove(userKey)
            }
        }

        cacheInitialized.set(true)
    }

    /** Detects whether a stored key is encrypted: metadata map, then legacy heuristic. */
    @PublishedApi
    internal fun detectProtection(key: String): KSafeProtection? {
        // No encrypted entry ever seen ⇒ definitely plaintext; skip the map lookups.
        if (!hasAnyEncryptedKey.get()) return null

        // Metadata is authoritative (including the explicit "NONE" literal); the legacy
        // heuristic applies only to keys never rewritten through the current format.
        val meta = protectionMap[key]
        if (meta != null) return KeySafeMetadataManager.parseProtection(meta)
        return if (memoryCache.containsKey(legacyEncryptedRawKey(key))) KSafeProtection.DEFAULT else null
    }

    private fun startWriteConsumer() {
        writeScope.launch {
            val batch = mutableListOf<PendingWrite>()
            while (isActive) {
                batch.add(writeChannel.receive())

                // Greedy drain: take everything already queued so a burst of writes
                // coalesces into a single applyBatch transaction.
                while (batch.size < maxBatchSize) {
                    val next = writeChannel.tryReceive().getOrNull() ?: break
                    batch.add(next)
                }

                // The coalesce window applies only when nobody is awaiting a commit —
                // awaiting puts skip it so a single suspend put completes in ~one round-trip.
                if (batch.size < maxBatchSize && batch.none { it.completion != null }) {
                    val windowStart = TimeSource.Monotonic.markNow()
                    while (batch.size < maxBatchSize) {
                        val remaining = writeCoalesceWindowMs - windowStart.elapsedNow().inWholeMilliseconds
                        if (remaining <= 0) break
                        val next = withTimeoutOrNull(remaining) { writeChannel.receive() } ?: break
                        batch.add(next)
                        // A waiter ends the window early.
                        if (next.completion != null) break
                    }
                }

                runCatching { processBatch(batch) }
                    .onFailure { e ->
                        if (e is CancellationException) throw e
                        // Awaiters were already failed inside processBatch; this log is
                        // for fire-and-forget callers with no Deferred to listen on.
                        println(
                            "KSafe SEVERE: processBatch failed " +
                                "(${e::class.simpleName}: ${e.message}); " +
                                "dropped ${batch.size} fire-and-forget write(s)."
                        )
                    }
                batch.clear()
            }
        }
    }

    private suspend fun processBatch(batch: List<PendingWrite>) {
        if (batch.isEmpty()) return

        val deferreds = batch.mapNotNull { it.completion }

        var failure: Throwable? = null
        try {
            processBatchBody(batch)
        } catch (e: Throwable) {
            if (e is CancellationException) {
                // Cancellation propagates to callers so they don't hang.
                deferreds.forEach { it.cancel(e) }
                throw e
            }
            failure = e
        }

        if (failure != null) {
            deferreds.forEach { it.completeExceptionally(failure) }
            throw failure  // surfaces to startWriteConsumer's runCatching for logging
        } else {
            deferreds.forEach { it.complete(Unit) }
        }
    }

    private suspend fun processBatchBody(batch: List<PendingWrite>) {
        // The last ClearAll is a batch boundary: everything before it is wiped and only
        // later writes survive — FIFO ordering keeps an earlier put from resurrecting data.
        val lastClear = batch.indexOfLast { it is PendingWrite.ClearAll }
        if (lastClear >= 0) {
            performClearAll()
            val after = batch.subList(lastClear + 1, batch.size)
            if (after.isNotEmpty()) processWrites(after)
            return
        }
        processWrites(batch)
    }

    /** The wipe for [clearAll]; runs on the write consumer, serialized with other writes. */
    private suspend fun performClearAll() {
        // Per-entry engine keys are deleted BEFORE clearing protectionMap (the key
        // inventory). For master-alias entries the per-entry delete is a harmless no-op.
        val encryptedUserKeys = protectionMap.snapshot()
            .filterValues { KeySafeMetadataManager.parseProtection(it) != null }
            .keys
        for (userKey in encryptedUserKeys) {
            runCatching { engine.deleteKeySuspend(keyAlias(userKey)) }
                .onFailure { if (it is CancellationException) throw it }
        }
        storage.clear()
        memoryCache.clear()
        plaintextCache.clear()
        protectionMap.clear()
        encMetaMap.clear()
        // Drop both master keys so the next datastore use starts from scratch.
        for (reqUnlocked in listOf(false, true)) {
            runCatching { engine.deleteKeySuspend(masterAlias(reqUnlocked)) }
                .onFailure { if (it is CancellationException) throw it }
        }
    }

    private suspend fun processWrites(batch: List<PendingWrite>) {
        val aliasesToDelete = mutableListOf<String>()
        val encryptedCiphertext = mutableMapOf<String, ByteArray>()

        // Coalesce to the LAST write per userKey: every op fully determines a key's final
        // state, so applying only the last op per key is equivalent to applying the window in
        // order. It also stops a same-batch delete+put from both running — the delete's
        // engine.deleteKey would otherwise orphan the just-written entry's per-entry key.
        val finalByKey = LinkedHashMap<String, PendingWrite>()
        for (op in batch) finalByKey[op.userKey] = op

        val toEncrypt = finalByKey.values.filterIsInstance<PendingWrite.Encrypted>()

        // Encrypt the deduped set concurrently. Per-op failure isolation: a coalesced batch
        // mixes unrelated keys, so a single failing encrypt (e.g. a requireUnlockedDevice write
        // on a locked device) must NOT drop the whole batch — each outcome is captured
        // independently rather than cancelling siblings via awaitAll's fail-fast. The offending
        // key is excluded, its awaiters failed, and its optimistic cache rolled back below.
        val encryptFailures = LinkedHashMap<String, Throwable>()
        if (toEncrypt.isNotEmpty()) {
            val gate = Semaphore(maxParallelEncrypts)
            val results = coroutineScope {
                toEncrypt.map { op ->
                    async {
                        gate.withPermit {
                            val alias = aliasForWrite(op.userKey, op.protection, op.requireUnlockedDevice)
                            op.userKey to try {
                                Result.success(
                                    engine.encryptSuspend(
                                        identifier = alias,
                                        data = op.jsonString.encodeToByteArray(),
                                        hardwareIsolated = op.protection == KSafeProtection.HARDWARE_ISOLATED,
                                        requireUnlockedDevice = op.requireUnlockedDevice,
                                    )
                                )
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Throwable) {
                                Result.failure(e)
                            }
                        }
                    }
                }.awaitAll()
            }
            for ((k, result) in results) {
                result.onSuccess { encryptedCiphertext[k] = it }
                    .onFailure { encryptFailures[k] = it }
            }
        }

        val ops = mutableListOf<StorageOp>()
        for (op in finalByKey.values) {
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
                    // Encrypt failed for this key — exclude it from the commit;
                    // its awaiter(s) are failed and its cache rolled back below.
                    if (op.userKey in encryptFailures) continue
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
                // Handled as a batch boundary in processBatchBody; never reaches
                // here (this branch only satisfies `when` exhaustiveness).
                is PendingWrite.ClearAll -> Unit
            }
        }

        if (ops.isNotEmpty()) {
            try {
                storage.applyBatch(ops)
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
                // Whole-batch persistence failed (e.g. disk-full IOException).
                // Roll back the optimistic cache for every key in this batch so
                // reads stop serving never-persisted values, then surface the
                // failure — processBatch fails all awaiters and logs.
                rollbackOptimisticState(finalByKey.values)
                throw e
            }
        }

        // Best-effort per-entry key cleanup, run AFTER the commit: a failure must not fail an
        // already-persisted batch. A stranded engine key is reclaimed by the orphan sweep.
        for (alias in aliasesToDelete) {
            runCatching { engine.deleteKeySuspend(alias) }
                .onFailure { if (it is CancellationException) throw it }
        }

        // Post-commit cache maintenance. Ciphertext-at-rest policies swap plaintext → ciphertext
        // under a CAS guard so a newer putDirect issued mid-batch isn't overwritten. Then REPAIR:
        // a clearAll ordered before this op may have wiped its optimistic in-memory state, so an op
        // still owning the key (writeOwners token) re-asserts it via putIfAbsent — restoring a wiped
        // slot without touching a newer write's value. Failed-encrypt keys have no ciphertext.
        for (op in finalByKey.values) {
            when (op) {
                is PendingWrite.Encrypted -> if (op.userKey !in encryptFailures) {
                    // Strict entries always settle to ciphertext in cache (even under a plaintext
                    // policy) so reads native-decrypt and enforce the lock; mirrors updateCache.
                    val cacheValue: Any = if (cacheHoldsCiphertext || op.requireUnlockedDevice) {
                        val base64 = b64Encode(encryptedCiphertext[op.userKey]!!)
                        memoryCache.replaceIf(op.rawCacheKey, op.jsonString, base64)
                        base64
                    } else {
                        op.jsonString
                    }
                    if (writeOwners[op.userKey] === op.writeToken) {
                        val protLiteral = KeySafeMetadataManager.protectionToLiteral(op.protection)
                        val meta = EncMeta(
                            envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_LATEST,
                            requireUnlockedDevice = op.requireUnlockedDevice,
                        )
                        memoryCache.putIfAbsent(op.rawCacheKey, cacheValue)
                        postCommitRepairHook?.invoke(op.userKey) // test-only interleaving seam; null in production
                        protectionMap.putIfAbsent(op.userKey, protLiteral)
                        encMetaMap.putIfAbsent(op.userKey, meta)
                        // TOCTOU guard: if we lost ownership between the check above and these
                        // inserts, undo exactly what we restored without clobbering a newer
                        // writer's identically-valued metadata. Coupled to the cache value:
                        //  • a newer PUT re-cached its own (different) value first, so
                        //    removeIf(cacheValue) fails and we leave its metadata intact;
                        //  • a DELETE wiped all three maps, so our metadata putIfAbsent
                        //    resurrected orphans for a now-valueless key — drop them.
                        if (writeOwners[op.userKey] !== op.writeToken) {
                            if (memoryCache.removeIf(op.rawCacheKey, cacheValue)) {
                                protectionMap.removeIf(op.userKey, protLiteral)
                                encMetaMap.removeIf(op.userKey, meta)
                            } else if (!memoryCache.containsKey(op.rawCacheKey)) {
                                protectionMap.removeIf(op.userKey, protLiteral)
                                encMetaMap.removeIf(op.userKey, meta)
                            }
                        }
                    }
                }
                is PendingWrite.Plain -> if (writeOwners[op.userKey] === op.writeToken) {
                    val protLiteral = KeySafeMetadataManager.protectionToLiteral(null)
                    memoryCache.putIfAbsent(op.rawCacheKey, op.value)
                    postCommitRepairHook?.invoke(op.userKey) // test-only interleaving seam; null in production
                    protectionMap.putIfAbsent(op.userKey, protLiteral)
                    // TOCTOU guard, same two-path cleanup as the Encrypted branch: if we lost
                    // ownership, either our value is still cached (removeIf → coupled rollback)
                    // or a DELETE wiped it and our putIfAbsent resurrected an orphan literal for
                    // a now-valueless key — drop it.
                    if (writeOwners[op.userKey] !== op.writeToken) {
                        if (memoryCache.removeIf(op.rawCacheKey, op.value)) {
                            protectionMap.removeIf(op.userKey, protLiteral)
                        } else if (!memoryCache.containsKey(op.rawCacheKey)) {
                            protectionMap.removeIf(op.userKey, protLiteral)
                        }
                    }
                }
                // A delete's desired in-memory state IS the wiped state.
                is PendingWrite.Delete, is PendingWrite.ClearAll -> Unit
            }
        }

        // Per-op encrypt failures: successful ops are already committed; roll back the dropped
        // keys' optimistic cache BEFORE failing their awaiters, so a caller that catches the
        // exception and immediately re-reads sees the reverted value, not the phantom.
        if (encryptFailures.isNotEmpty()) {
            rollbackOptimisticState(finalByKey.values.filter { it.userKey in encryptFailures })
            // Iterate the COALESCED final ops, not the raw batch: only a key's final op is
            // encrypted, so failing the raw batch would also hand an unrelated keystore
            // exception to an earlier superseded op for the same key.
            for (op in finalByKey.values) {
                val cause = encryptFailures[op.userKey] ?: continue
                op.completion?.completeExceptionally(cause)
            }
            val sample = encryptFailures.entries.first()
            println(
                "KSafe SEVERE: ${encryptFailures.size} encrypted write(s) failed and " +
                    "were rolled back (other writes in the batch committed); e.g. " +
                    "key='${sample.key}' (${sample.value::class.simpleName}: " +
                    "${sample.value.message}). Awaiting callers received the exception."
            )
        }
        // Successful-write dirty flags are deliberately NOT cleared: they keep
        // stale collector snapshots from clobbering optimistic writes.
    }

    /**
     * Reverts optimistic in-memory state for failed writes and reconciles the keys against
     * disk via [updateCache] (a previously-persisted value is restored, a never-persisted one
     * is evicted). Ownership gate: a failed op only rolls back a key it still OWNS
     * (`writeOwners[key] === op.writeToken`); a newer write for the same key now owns the dirty
     * flags and optimistic cache, so clearing them here would strip its state.
     */
    private suspend fun rollbackOptimisticState(failedOps: Collection<PendingWrite>) {
        var rolledBackAny = false
        for (op in failedOps) {
            val key = op.userKey
            if (writeOwners[key] !== op.writeToken) continue
            rolledBackAny = true
            dirtyKeys.remove(valueRawKey(key))
            dirtyKeys.remove(legacyEncryptedRawKey(key))
            dirtyKeys.remove(key)
            // updateCache does NOT manage the secondary plaintextCache, so evict
            // the failed key's optimistic plaintext here too — otherwise reads
            // under ENCRYPTED_WITH_TIMED_CACHE / LAZY_PLAIN_TEXT keep serving the
            // phantom from the side cache (permanently, under LAZY_PLAIN_TEXT
            // which never expires). Covers both rawCacheKey forms (encrypted =
            // legacyEncryptedRawKey, plain = userKey).
            plaintextCache.remove(legacyEncryptedRawKey(key))
            plaintextCache.remove(key)
        }
        if (!rolledBackAny) return
        runCatching { updateCache(storage.snapshot()) }
            .onFailure { if (it is CancellationException) throw it }
    }

    // ============================================================
    // Raw read/write API (all inline wrappers in KSafe delegate here)
    // ============================================================

    @PublishedApi
    internal fun getDirectRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        ensureCacheReadyBlocking()
        val detected = detectProtection(key)
        return try {
            resolveFromCache(key, defaultValue, detected, serializer)
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
            // Non-suspend read path: resolveFromCache rethrows a TRANSIENT decrypt failure so a
            // suspending caller can await unlock and retry, but getDirect (and the delegate /
            // StateFlow / Compose seed sites funnelling here) has no retry seam and must return
            // the default — letting it escape would crash property access / composition on a
            // locked device. The suspend get() path (getRaw) still rethrows.
            if (isTransientDecryptFailure(e)) defaultValue else throw e
        }
    }

    @PublishedApi
    internal suspend fun getRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any? {
        ensureCacheReadySuspend()
        val detected = detectProtection(key)
        return withContext(Dispatchers.Default) {
            resolveFromCache(key, defaultValue, detected, serializer)
        }
    }

    /**
     * Per-emission sentinel: a transient decrypt failure maps to this and is filtered
     * out, so the emission is **skipped** rather than crashing the flow.
     */
    private val transientDecryptSkip = Any()

    /**
     * A transient decrypt failure (locked device / busy Keystore) skips that emission rather
     * than throwing: this flow is collected by long-lived observers (viewModelScope / Recomposer)
     * where an uncaught throw would crash the app and permanently stop observation. Skipping keeps
     * the flow and its last value alive; the next decryptable snapshot updates it.
     */
    @PublishedApi
    internal fun getFlowRaw(
        key: String,
        defaultValue: Any?,
        serializer: KSerializer<*>,
    ): Flow<Any?> {
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
                            // Snapshot-based read: derive the alias from the meta we
                            // just parsed, not from encMetaMap (which may lag behind
                            // a freshly arrived snapshot). v2 + DEFAULT routes to the
                            // master alias; everything else uses the per-entry alias.
                            val envVersion = KeySafeMetadataManager.parseEnvelopeVersion(metaRaw)
                            val requireUnlocked = KeySafeMetadataManager.parseRequireUnlockedDevice(metaRaw)
                            val alias = if (envVersion >= KeySafeMetadataManager.ENVELOPE_VERSION_V2 &&
                                protection == KSafeProtection.DEFAULT
                            ) {
                                masterAlias(requireUnlocked)
                            } else {
                                keyAlias(key)
                            }
                            // Pass the recorded unlock policy so a strict entry bypasses the
                            // engine's in-memory key cache and the native store enforces the lock
                            // on every emission. On a locked device the strict decrypt throws
                            // transient and the emission is skipped below.
                            val plainBytes = engine.decryptSuspend(alias, b64Decode(enc), requireUnlocked)
                            val rawString = plainBytes.decodeToString()
                            if (rawString == NULL_SENTINEL) null
                            else jsonDecode(json, serializer, rawString)
                        } catch (e: Throwable) {
                            if (e is CancellationException) throw e
                            // Transient (locked device / busy Keystore): skip this emission
                            // (filtered below) so collectors aren't crashed.
                            if (isTransientDecryptFailure(e)) transientDecryptSkip
                            else defaultValue
                        }
                    } else defaultValue
                }
            }
        }
            // Decrypt each snapshot off the collector's dispatcher: the .map above runs
            // engine.decryptSuspend (on Android a blocking Binder round-trip to the Keystore),
            // and stateIn collects on the caller's scope (often Main), so without flowOn every
            // emission would run keystore IPC on the main thread → ANR. decryptFlowContext is
            // Dispatchers.Default on JVM/Android/Apple, a no-op on single-threaded web; the
            // cheap filter/distinctUntilChanged stay in the collector's context.
            .flowOn(decryptFlowContext)
            .filter { it !== transientDecryptSkip }
            .distinctUntilChanged()
    }

    @PublishedApi
    internal fun putDirectRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) {
        @Suppress("NAME_SHADOWING") val mode = modeTransformer(mode)
        val protection = mode.toProtection()
        val requireUnlockedDevice = mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice

        // Claim rollback ownership FIRST — before any optimistic mutation — so
        // a concurrently-failing older write for this key can no longer revert
        // the state set below.
        val writeToken = Any().also { writeOwners[key] = it }

        if (protection != null) {
            val rawCacheKey = legacyEncryptedRawKey(key)
            dirtyKeys.add(rawCacheKey)

            val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
            memoryCache[rawCacheKey] = jsonString
            protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(protection)
            encMetaMap[key] = EncMeta(
                envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_LATEST,
                requireUnlockedDevice = requireUnlockedDevice,
            )
            hasAnyEncryptedKey.set(true)

            // Strict entries never enter the plaintext side cache (leaving plaintext in a
            // never-expiring cache would defeat the lock policy in memory); a non-strict→strict
            // rewrite also evicts any prior entry so stale plaintext doesn't linger.
            if (usesPlaintextSideCache) {
                if (requireUnlockedDevice) plaintextCache.remove(rawCacheKey)
                else plaintextCache[rawCacheKey] = CachedPlaintext(jsonString, plaintextExpiry())
            }

            writeChannel.trySend(
                PendingWrite.Encrypted(
                    userKey = key,
                    rawCacheKey = rawCacheKey,
                    jsonString = jsonString,
                    protection = protection,
                    requireUnlockedDevice = requireUnlockedDevice,
                    writeToken = writeToken,
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
            encMetaMap.remove(key)

            val storedInBatch: Any = if (value == null) NULL_SENTINEL
            else when (value) {
                is Boolean, is Int, is Long, is Float, is Double, is String -> value
                else -> jsonEncode(json, serializer, value)
            }
            writeChannel.trySend(
                PendingWrite.Plain(userKey = key, rawCacheKey = rawCacheKey, value = storedInBatch, writeToken = writeToken)
            )
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
        // Optimistic in-memory state (matches `putEncryptedDirect`): subsequent
        // reads from any thread see the new value the instant this returns.
        // Rollback ownership claimed before any optimistic mutation.
        val writeToken = Any().also { writeOwners[key] = it }
        val rawCacheKey = legacyEncryptedRawKey(key)
        dirtyKeys.add(rawCacheKey)
        protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(protection)
        encMetaMap[key] = EncMeta(
            envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_LATEST,
            requireUnlockedDevice = requireUnlockedDevice,
        )
        hasAnyEncryptedKey.set(true)

        val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
        memoryCache[rawCacheKey] = jsonString
        // Strict entries never enter the plaintext side cache; a non-strict→strict rewrite
        // also evicts any prior entry so stale plaintext doesn't linger.
        if (usesPlaintextSideCache) {
            if (requireUnlockedDevice) plaintextCache.remove(rawCacheKey)
            else plaintextCache[rawCacheKey] = CachedPlaintext(jsonString, plaintextExpiry())
        }

        // Route through the same coalescing channel as `putDirect`, but await the
        // batch's commit. Concurrent suspend `put` calls and concurrent `putDirect`
        // calls land in the same batch and share a single `applyBatch` transaction.
        val deferred = CompletableDeferred<Unit>()
        writeChannel.send(
            PendingWrite.Encrypted(
                userKey = key,
                rawCacheKey = rawCacheKey,
                jsonString = jsonString,
                protection = protection,
                requireUnlockedDevice = requireUnlockedDevice,
                writeToken = writeToken,
                completion = deferred,
            )
        )
        deferred.await()
    }

    private suspend fun putPlainSuspend(key: String, value: Any?, serializer: KSerializer<*>) {
        // Optimistic in-memory state (matches `putPlainDirect`).
        // Rollback ownership claimed before any optimistic mutation.
        val writeToken = Any().also { writeOwners[key] = it }
        dirtyKeys.add(key)

        val toCache: Any = if (value == null) NULL_SENTINEL
        else when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> value
            else -> jsonEncode(json, serializer, value)
        }
        // Cache the value BEFORE the protection literal — the post-commit repair's orphan
        // cleanup (`!memoryCache.containsKey`) relies on this ordering.
        memoryCache[key] = toCache
        protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(null)
        encMetaMap.remove(key)

        val storedInBatch: Any = if (value == null) NULL_SENTINEL
        else when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> value
            else -> jsonEncode(json, serializer, value)
        }

        val deferred = CompletableDeferred<Unit>()
        writeChannel.send(
            PendingWrite.Plain(
                userKey = key,
                rawCacheKey = key,
                value = storedInBatch,
                writeToken = writeToken,
                completion = deferred,
            )
        )
        deferred.await()
    }

    fun deleteDirect(key: String) {
        // Rollback ownership claimed before any optimistic mutation.
        val writeToken = Any().also { writeOwners[key] = it }
        val rawKey = key
        val encKeyName = legacyEncryptedRawKey(key)
        dirtyKeys.add(rawKey)
        dirtyKeys.add(encKeyName)
        memoryCache.remove(rawKey)
        memoryCache.remove(encKeyName)
        plaintextCache.remove(rawKey)
        plaintextCache.remove(encKeyName)
        protectionMap.remove(key)
        encMetaMap.remove(key)
        writeChannel.trySend(PendingWrite.Delete(userKey = key, rawCacheKey = rawKey, writeToken = writeToken))
    }

    suspend fun delete(key: String) {
        // Optimistic in-memory cleanup (matches `deleteDirect`).
        // Rollback ownership claimed before any optimistic mutation.
        val writeToken = Any().also { writeOwners[key] = it }
        val rawKey = key
        val encKeyName = legacyEncryptedRawKey(key)
        dirtyKeys.add(rawKey)
        dirtyKeys.add(encKeyName)
        memoryCache.remove(rawKey)
        memoryCache.remove(encKeyName)
        plaintextCache.remove(rawKey)
        plaintextCache.remove(encKeyName)
        protectionMap.remove(key)
        encMetaMap.remove(key)

        // Route through the coalescer so concurrent deletes + writes share batches.
        val deferred = CompletableDeferred<Unit>()
        writeChannel.send(
            PendingWrite.Delete(
                userKey = key,
                rawCacheKey = rawKey,
                writeToken = writeToken,
                completion = deferred,
            )
        )
        deferred.await()
    }

    suspend fun clearAll() {
        // Populate the cache first so performClearAll() (which runs on the write
        // consumer) can read protectionMap to learn which per-entry engine keys
        // to delete — covers clearAll() on a fresh/lazyLoad instance, before the
        // first snapshot has populated the map.
        ensureCacheReadySuspend()
        // Route the wipe THROUGH the write channel (instead of clearing storage
        // directly) so it is serialized with concurrent writes by the single
        // consumer: a put/delete enqueued before this call is ordered before the
        // wipe and can no longer be applied after it and resurrect data. Like the
        // suspend put/delete paths, this awaits the consumer (don't call it on a
        // closed instance).
        val deferred = CompletableDeferred<Unit>()
        writeChannel.send(PendingWrite.ClearAll(completion = deferred))
        deferred.await()
    }

    fun getKeyInfo(key: String): KSafeKeyInfo? {
        ensureCacheReadyBlocking()
        val hasEncrypted = memoryCache.containsKey(legacyEncryptedRawKey(key))
        val hasPlain = memoryCache.containsKey(key)
        // An entry can EXIST on disk yet be absent from memoryCache: under PLAIN_TEXT, updateCache
        // drops entries that fail to decrypt (locked device / corrupt blob) but still syncs their
        // protection into protectionMap. Consult it too, so getOrCreateSecret doesn't mint a new
        // secret over a still-present but unreadable one and orphan everything encrypted under it.
        val hasMetadata = protectionMap.containsKey(key)
        if (!hasEncrypted && !hasPlain && !hasMetadata) return null
        val protection = KeySafeMetadataManager.parseProtection(protectionMap[key])
            ?: if (hasEncrypted) KSafeProtection.DEFAULT else null
        @Suppress("DEPRECATION")
        return KSafeKeyInfo(
            protection = protection,
            storage = resolveKeyStorage(key, protection),
            level = resolveKeyLevel(key, protection),
        )
    }

    // ============================================================
    // Cache resolution
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

            val reqUnlocked = encMetaMap[key]?.requireUnlockedDevice == true

            // Strict (requireUnlockedDevice) entries ALWAYS take the native-decrypt branch, even
            // under a plaintext memory policy, so a locked-device read never returns the secret
            // straight from RAM. Their slot normally holds ciphertext, but TRANSIENTLY holds
            // plaintext during the optimistic write window — so the failure path below must also
            // refuse to fall through to that plaintext (the reqUnlocked guard on the fallback).
            if (cacheHoldsCiphertext || reqUnlocked) {
                if (usesPlaintextSideCache && !reqUnlocked) {
                    val cached = plaintextCache[cacheKey]
                    if (cached != null && plaintextStillValid(cached)) {
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
                        val plainBytes = engine.decrypt(aliasForRead(key, protection), b64Decode(encryptedString), reqUnlocked)
                        val candidate = plainBytes.decodeToString()
                        deserialized = if (candidate == NULL_SENTINEL) null
                        else jsonDecode(json, serializer, candidate)
                        success = true
                        // Guarded write-back: the decrypt is a slow round-trip during which a
                        // put/delete may have landed, so only repopulate the side cache when the
                        // primary still holds the exact ciphertext we decrypted (CAS discipline) —
                        // otherwise we'd serve stale plaintext, permanently under LAZY_PLAIN_TEXT.
                        if (usesPlaintextSideCache && !reqUnlocked && memoryCache[cacheKey] == encryptedString) {
                            plaintextCache[cacheKey] = CachedPlaintext(candidate, plaintextExpiry())
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
            // A strict entry must NEVER fall through to the cached value when native-decrypt
            // didn't succeed: during the optimistic write window the slot transiently holds
            // plaintext, and serving it would return the secret from RAM on a locked device.
            // Return the default instead (a committed strict entry holds ciphertext here anyway).
            if (reqUnlocked) return defaultValue
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

        // Dispatch on the serializer's primitive kind, not defaultValue's runtime class: that
        // survives a null default and is JS-safe (on Kotlin/JS `0f is Int` is true). Built-in
        // primitives ONLY — a custom serializer with a primitive descriptor (Duration, Uuid,
        // datetime) is JSON-encoded by the write path, so it must round-trip through the JSON
        // else-branch; the primitive fast-path would return stored JSON verbatim and the
        // caller's reified cast would throw CCE.
        return when (builtInPrimitiveKindOrNull(serializer)) {
            kotlinx.serialization.descriptors.PrimitiveKind.BOOLEAN -> when (storedValue) {
                is Boolean -> storedValue
                is String -> storedValue.toBooleanStrictOrNull() ?: defaultValue
                else -> defaultValue
            }
            // Numeric kinds coerce across the whole Int/Long/Float/Double matrix so a key's
            // declared type can change between app versions without losing data: coerce when the
            // value is faithfully representable, else fall back to the default (out-of-range or
            // fractional reads) rather than silently truncating or wrapping. Widening conversions
            // are exact or lose only precision at large magnitudes.
            kotlinx.serialization.descriptors.PrimitiveKind.INT -> when (storedValue) {
                is Int -> storedValue
                is Long -> if (storedValue in Int.MIN_VALUE..Int.MAX_VALUE) storedValue.toInt() else defaultValue
                is Float -> storedValue.toDouble().toLongExactOrNull()
                    ?.let { if (it in Int.MIN_VALUE..Int.MAX_VALUE) it.toInt() else null } ?: defaultValue
                is Double -> storedValue.toLongExactOrNull()
                    ?.let { if (it in Int.MIN_VALUE..Int.MAX_VALUE) it.toInt() else null } ?: defaultValue
                is String -> storedValue.toIntOrNull() ?: defaultValue
                else -> defaultValue
            }
            kotlinx.serialization.descriptors.PrimitiveKind.LONG -> when (storedValue) {
                is Long -> storedValue
                is Int -> storedValue.toLong()
                is Float -> storedValue.toDouble().toLongExactOrNull() ?: defaultValue
                is Double -> storedValue.toLongExactOrNull() ?: defaultValue
                is String -> storedValue.toLongOrNull() ?: defaultValue
                else -> defaultValue
            }
            kotlinx.serialization.descriptors.PrimitiveKind.FLOAT -> when (storedValue) {
                is Float -> storedValue
                // Narrowing Double -> Float, mirroring the Long -> Int guard: a finite
                // Double that overflows Float's range falls back to the default rather
                // than silently becoming Infinity.
                is Double -> {
                    val f = storedValue.toFloat()
                    if (f.isInfinite() && storedValue.isFinite()) defaultValue else f
                }
                // Int / Long -> Float never overflows Float's range; large magnitudes
                // lose precision, which is the expected narrowing cost.
                is Int -> storedValue.toFloat()
                is Long -> storedValue.toFloat()
                is String -> storedValue.toFloatOrNull() ?: defaultValue
                else -> defaultValue
            }
            kotlinx.serialization.descriptors.PrimitiveKind.DOUBLE -> when (storedValue) {
                is Double -> storedValue
                is Float -> storedValue.toDouble()   // widening — lossless
                is Int -> storedValue.toDouble()     // exact — Int fits Double's 53-bit mantissa
                is Long -> storedValue.toDouble()    // representable; magnitudes > 2^53 lose precision (expected)
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

    /**
     * Returns this Double as a Long if it is finite, has no fractional part, and
     * fits within Long's range; otherwise null. Used for decimal -> integer reads
     * (see [convertStoredValue]) so a fractional or out-of-range decimal falls back
     * to the caller's default instead of being silently truncated or wrapped.
     */
    private fun Double.toLongExactOrNull(): Long? {
        if (!isFinite() || this != kotlin.math.floor(this)) return null
        // Long.MAX_VALUE.toDouble() rounds up to 2^63 (out of Long range), so the
        // upper bound is strict; Long.MIN_VALUE (-2^63) is exactly representable.
        if (this < Long.MIN_VALUE.toDouble() || this >= Long.MAX_VALUE.toDouble()) return null
        return toLong()
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
        // Best-effort cold-start freshness. Android/iOS/JVM block once to
        // populate the cache; web can't block so the call throws and we fall
        // through — a concurrent `getDirect` there returns its default until
        // the background preload completes.
        try {
            runBlockingOnPlatform {
                if (!cacheInitialized.get()) updateCache(storage.snapshot())
            }
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
            /* web: no blocking available */
        }
        // lazyLoad has no collector to run the one-time startup cleanup — trigger it once
        // here, off the caller's thread, now that a first access has readied the cache.
        triggerLazyStartupCleanupOnce()
    }

    suspend fun ensureCacheReadySuspend() {
        if (cacheInitialized.get()) {
            triggerLazyStartupCleanupOnce()
            return
        }
        updateCache(storage.snapshot())
        triggerLazyStartupCleanupOnce()
    }

    /**
     * Cancels both background scopes (write consumer + snapshot collector), releasing the
     * long-running infrastructure this core owns. Idempotent; after cancel the instance no
     * longer processes puts/reads. Mainly matters for test suites and code that re-creates
     * KSafe mid-process: without it each abandoned instance is pinned in heap by its suspended
     * coroutines (GC roots on Dispatchers.Default), growing the live-set unboundedly.
     */
    internal fun cancel() {
        // Cancel the scopes only — do NOT close writeChannel: closing it makes the consumer's
        // pending receive() throw ClosedReceiveChannelException (not a CancellationException),
        // which bubbles to the uncaught handler and surfaces in the next test. Cancelling the
        // scope already terminates the consumer, and the channel is then GC'd with the core.
        writeScope.cancel()
        collectorScope.cancel()
        // Platform hook — cancels the DataStore scope and evicts Android's process-static
        // DataStore cache; without it DataStore's coroutines pin the whole graph in heap.
        runCatching { onCancel() }
    }

    private fun isTransientDecryptFailure(e: Throwable): Boolean {
        val msg = e.message ?: return false
        // KSafe's OWN definitive results (key absent, vault unavailable) are never retryable —
        // exclude them first so a store literally named "keystore" doesn't get its missing-key
        // reads misclassified as a retryable hiccup and throw instead of returning the default.
        if (msg.contains("No encryption key found", ignoreCase = true) ||
            msg.contains("key not found", ignoreCase = true) ||
            msg.contains("vault unavailable", ignoreCase = true)
        ) {
            return false
        }
        // Android Keystore (device locked / Keystore crashed) and iOS Keychain (locked keychain /
        // Secure Enclave busy) surface as recognisable message strings; JVM software encryption
        // never produces these. Treated as retryable so callers can await unlock rather than
        // silently getting the default.
        return msg.contains("device is locked", ignoreCase = true) ||
            msg.contains("Keystore", ignoreCase = true) ||
            msg.contains("Keychain", ignoreCase = true)
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
