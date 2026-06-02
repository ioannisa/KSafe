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
     *
     * Legacy three-value vocabulary — see [resolveKeyLevel] for the
     * universally-ordered [KSafeProtectionLevel] scale that additionally
     * distinguishes JVM OS-vault keys from the plaintext-in-file fallback.
     */
    private val resolveKeyStorage: (userKey: String, protection: KSafeProtection?) -> KSafeKeyStorage,
    /**
     * Resolves the per-key protection level on the universally-ordered
     * [KSafeProtectionLevel] scale. Parallel to [resolveKeyStorage]; populates
     * the new [KSafeKeyInfo.level] field.
     *
     * Platform mapping:
     *  - **Android:** `null` (plain) → SOFTWARE; HARDWARE_ISOLATED-on-StrongBox
     *    → HARDWARE_ISOLATED; otherwise HARDWARE_BACKED.
     *  - **Apple:** same, with Secure Enclave.
     *  - **JVM:** `null` → SOFTWARE; encrypted → SANDBOX_PROTECTED if the
     *    active vault is OS-backed (DPAPI/Keychain/SecretService), SOFTWARE
     *    when the fallback / opt-out is active.
     *  - **Web:** `null` → SOFTWARE; encrypted → SANDBOX_PROTECTED (browser
     *    origin enforces non-extractability).
     */
    private val resolveKeyLevel: (userKey: String, protection: KSafeProtection?) -> KSafeProtectionLevel,
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
     * Builds the master Keystore/Keychain alias for the current datastore.
     * Two aliases per datastore — one for relaxed accessibility
     * (`requireUnlockedDevice = false`) and one for strict
     * (`requireUnlockedDevice = true`). These hold AES keys shared across all
     * v2 [KSafeProtection.DEFAULT] entries; HARDWARE_ISOLATED entries always
     * use per-entry keys built via [keyAlias].
     *
     * Platform shells derive the master alias from the datastore filename
     * using the same scheme as [keyAlias], substituting a reserved sentinel
     * for the user-key part. JVM collapses both variants to a single alias
     * (no lock concept on JVM, so the second key would be unused).
     */
    @PublishedApi internal val masterAlias: (requireUnlockedDevice: Boolean) -> String,
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

    /**
     * Per-encrypted-key envelope info. Tracks the envelope version (v1 or v2)
     * and the per-entry `requireUnlockedDevice` recorded in metadata. The
     * combination tells the read path which alias to decrypt under: v2 +
     * `protection == DEFAULT` routes to the master alias picked by
     * `requireUnlockedDevice`; otherwise the per-entry alias is used.
     *
     * Plain entries are never present in this map.
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
     * `true` for any policy whose primary [memoryCache] holds Base64 ciphertext at rest:
     * [KSafeMemoryPolicy.ENCRYPTED], [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE], and
     * [KSafeMemoryPolicy.LAZY_PLAIN_TEXT]. Cold-start skips bulk decryption and the post-batch
     * CAS swap rewrites optimistic plaintext to ciphertext.
     */
    private val cacheHoldsCiphertext: Boolean =
        memoryPolicy == KSafeMemoryPolicy.ENCRYPTED ||
            memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE ||
            memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT

    /**
     * `true` for policies that maintain the secondary [plaintextCache]:
     * [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE] (TTL-bounded) and
     * [KSafeMemoryPolicy.LAZY_PLAIN_TEXT] (permanent — no expiry check).
     */
    private val usesPlaintextSideCache: Boolean =
        memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE ||
            memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT

    /**
     * Returns `true` if a plaintext-side-cache entry is still considered fresh.
     * Under [KSafeMemoryPolicy.LAZY_PLAIN_TEXT] entries never expire — the side cache is
     * a permanent lazily-populated plaintext store. Under
     * [KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE] the configured TTL is honored.
     */
    private fun plaintextStillValid(cached: CachedPlaintext): Boolean =
        memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT ||
            TimeSource.Monotonic.markNow() < cached.expiresAt

    /**
     * Computes the [ComparableTimeMark] to stamp on a fresh plaintext-side-cache entry.
     * The value is unused by [plaintextStillValid] under [KSafeMemoryPolicy.LAZY_PLAIN_TEXT]
     * (which always returns `true`), so any sane value works there — we use "now" so the
     * arithmetic stays platform-safe across all KMP targets.
     */
    private fun plaintextExpiry(): ComparableTimeMark =
        if (memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT) TimeSource.Monotonic.markNow()
        else TimeSource.Monotonic.markNow() + plaintextCacheTtl

    @PublishedApi
    internal val cacheInitialized = KSafeAtomicFlag(false)

    /**
     * Tracks whether this instance has ever observed an encrypted entry — set on the first
     * encrypted write and on cache load if any encrypted entry is found on disk. Lets the
     * read fast path skip [detectProtection]'s map lookups entirely when the store contains
     * only plaintext values, which is the common case for apps using KSafe purely as a
     * settings cache. Monotonic: once true, never reset (the cost of a stuck-true flag is
     * one extra map lookup per read, identical to pre-flag behaviour).
     */
    @PublishedApi
    internal val hasAnyEncryptedKey = KSafeAtomicFlag(false)

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
    private val maxBatchSize = 200

    /**
     * Upper bound on concurrent in-flight encrypt calls inside [processBatch].
     * Hardware-keystore engines (Android/iOS) spend most of an encrypt on IPC to
     * the keystore daemon, so overlapping a handful of requests yields a real
     * pipeline win. The cap prevents flooding Binder / Keychain when batches are
     * large and keeps software engines from over-subscribing the dispatcher.
     */
    private val maxParallelEncrypts = 8

    init {
        startWriteConsumer()
        if (!lazyLoad) startBackgroundCollector()
        prewarmMasterKeys()
    }

    /**
     * Eagerly creates and caches both master keys (relaxed + strict) for this
     * datastore. Runs on the write scope so it doesn't block construction:
     * the worst case if the user issues a v2-DEFAULT write before this finishes
     * is one extra Keystore IPC inside the engine's `getOrCreateSecretKey`
     * lock — same outcome as the lazy-create path.
     *
     * The probe is a single `encryptSuspend(masterAlias, emptyBytes)` per
     * variant: it triggers `getOrCreateSecretKey` (creating the alias if
     * missing) and primes the engine's in-process key cache. The ciphertext
     * is discarded.
     *
     * Failures are swallowed — typical reasons are a locked device on first
     * launch (the strict variant requires unlock) or Keychain interaction-
     * not-allowed. Either way the lazy-create path will retry on first real
     * write.
     */
    private fun prewarmMasterKeys() {
        writeScope.launch {
            val probe = ByteArray(0)
            for (requireUnlocked in listOf(false, true)) {
                try {
                    engine.encryptSuspend(
                        identifier = masterAlias(requireUnlocked),
                        data = probe,
                        hardwareIsolated = false,
                        requireUnlockedDevice = requireUnlocked,
                    )
                } catch (e: Throwable) {
                    if (e is CancellationException) throw e
                    /* swallow — lazy path will retry on first real write */
                }
            }
        }
    }

    // ---- pending-write sealed hierarchy ----

    private sealed class PendingWrite {
        abstract val userKey: String
        abstract val rawCacheKey: String

        /**
         * Non-null when a caller is awaiting the disk commit (suspend `put` /
         * `delete`). Null for fire-and-forget `putDirect` / `deleteDirect`.
         * The consumer completes this after `applyBatch` succeeds, or
         * completes it exceptionally when the batch fails.
         */
        abstract val completion: CompletableDeferred<Unit>?

        data class Plain(
            override val userKey: String,
            override val rawCacheKey: String,
            /**
             * Either a primitive ([Boolean], [Int], [Long], [Float], [Double], [String])
             * or the null sentinel string. Complex `@Serializable` types are pre-encoded
             * to JSON and arrive here as [String].
             */
            val value: Any,
            override val completion: CompletableDeferred<Unit>? = null,
        ) : PendingWrite()

        data class Encrypted(
            override val userKey: String,
            override val rawCacheKey: String,
            val jsonString: String,
            val protection: KSafeProtection,
            val requireUnlockedDevice: Boolean,
            override val completion: CompletableDeferred<Unit>? = null,
        ) : PendingWrite()

        data class Delete(
            override val userKey: String,
            override val rawCacheKey: String,
            override val completion: CompletableDeferred<Unit>? = null,
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

    /**
     * Picks the encryption alias for a *write*. v2 envelope routes
     * [KSafeProtection.DEFAULT] through the master alias chosen by
     * [requireUnlockedDevice]; [KSafeProtection.HARDWARE_ISOLATED] always
     * uses the per-entry alias (the v2 marker is irrelevant for that branch).
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
     * Picks the decryption alias for a *read*. Looks up the entry's recorded
     * envelope version + unlock policy in [encMetaMap]; v2 + DEFAULT routes
     * to the master alias (chosen by the entry's recorded
     * `requireUnlockedDevice`); v1, plain, or HARDWARE_ISOLATED reads use
     * the per-entry alias.
     *
     * For entries that have no [encMetaMap] entry yet (e.g. legacy on-disk
     * data loaded before [updateCache] has populated it for that key), this
     * defaults to the v1 per-entry alias — the safe choice, since v1 was the
     * only on-disk envelope before this change.
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

    // ============================================================
    // Background collector — mirrors DataStore snapshotFlow into cache
    // ============================================================

    private fun startBackgroundCollector() {
        collectorScope.launch {
            // Run cleanup *after* the first snapshot has populated the cache.
            //
            // Why this order matters: on Apple platforms (iOS + macOS) the
            // 1.x → 2.0 path migration in `KSafe.apple.kt` moves the legacy
            // DataStore file from `NSDocumentDirectory` to
            // `NSApplicationSupportDirectory` immediately before the
            // DataStore is constructed. If cleanup ran first (the pre-fix
            // ordering), `storage.snapshot()` could return an empty map
            // whenever the move silently failed, the destination file got
            // created empty, or DataStore's read-after-move raced — and the
            // Keychain sweep would interpret "empty snapshot + populated
            // Keychain" as "every Keychain entry is orphaned" and call
            // `engine.deleteKeySuspend(...)` for each, *destroying the
            // Secure Enclave EC private keys*. Once the SE private keys
            // are gone they cannot be recreated (the SE never exports
            // them), so any ciphertext that survived the move is
            // permanently undecryptable.
            //
            // By contrast, observing one full `snapshotFlow` emission
            // first guarantees DataStore has finished its initial read.
            // If the migration succeeded, the snapshot reflects the moved
            // file and the sweep correctly preserves all live keys.
            //
            // If the migration *did* fail and the snapshot is genuinely
            // empty, the sweep will still delete Keychain entries — this
            // fix narrows the race window but does not eliminate the
            // empty-snapshot edge case entirely. A defensive guard inside
            // KeychainOrphanCleanup (refuse to delete when snapshot is
            // empty AND the Keychain has scoped entries) is the
            // belt-and-suspenders follow-up tracked separately.
            var firstEmission = true
            storage.snapshotFlow().collect { snapshot ->
                updateCache(snapshot)
                if (firstEmission) {
                    firstEmission = false
                    runCatching { migrateAccessPolicy() }
                        .onFailure { if (it is CancellationException) throw it }
                    runCatching { cleanupOrphanedCiphertext() }
                        .onFailure { if (it is CancellationException) throw it }
                    // Eager one-time sweep of pre-2.1 key material out of the
                    // weak location (JVM DataStore file / web localStorage)
                    // into the secure store. Best-effort, idempotent, no-op
                    // where there's no safer destination. Lazy per-key
                    // migration still handles correctness; this just shrinks
                    // the cold-key exposure window to one session.
                    runCatching { engine.migrateLegacyKeysSuspend() }
                        .onFailure { if (it is CancellationException) throw it }
                }
            }
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

        // Collect probe candidates first so the actual decrypt round-trips can run
        // concurrently. Each probe is a Keystore IPC call and they don't contend on
        // shared state — Semaphore caps in-flight count to avoid flooding Binder
        // / Keychain on stores with thousands of keys.
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
                            engine.decryptSuspend(aliasForRead(c.userKey, c.protection), b64Decode(c.ciphertextB64))
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
            orphanOps += StorageOp.Delete(c.rawKey)
            orphanOps += StorageOp.Delete(metaRawKey(c.userKey))
            orphanOps += StorageOp.Delete(legacyProtectionRawKey(c.userKey))
            memoryCache.remove(c.userKey)
            memoryCache.remove(legacyEncryptedRawKey(c.userKey))
        }
        storage.applyBatch(orphanOps)
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

        // Populate encMetaMap from on-disk metadata BEFORE the second-pass
        // decrypt — `aliasForRead` consults it to choose between the master
        // alias (v2 + DEFAULT) and the per-entry alias (v1 / HARDWARE_ISOLATED).
        // Legacy entries with no metadata or with literal-form metadata parse
        // as v1, which routes through the per-entry alias unchanged.
        for ((userKey, rawMeta) in protectionByKey) {
            if (isDirtyForUserKey(userKey)) continue
            // Skip plain entries — encMetaMap only tracks encrypted ones.
            if (KeySafeMetadataManager.parseProtection(rawMeta) == null) continue
            val env = KeySafeMetadataManager.parseEnvelopeVersion(rawMeta)
            val unlocked = KeySafeMetadataManager.parseRequireUnlockedDevice(rawMeta)
            encMetaMap[userKey] = EncMeta(envelopeVersion = env, requireUnlockedDevice = unlocked)
        }

        // First pass: classify, populate plain entries directly, stash ENCRYPTED-mode
        // ciphertexts directly. Defer PLAIN_TEXT-memory decrypts to a second pass so
        // they can run concurrently — each decrypt is a Keystore IPC round-trip and
        // serialising them dominates cold-start time when the store has many keys.
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
                if (cacheHoldsCiphertext) {
                    memoryCache[cacheKey] = encryptedString
                } else {
                    val protection = KeySafeMetadataManager.parseProtection(protectionByKey[userKey])
                        ?: KSafeProtection.DEFAULT
                    pendingDecrypts += PendingDecrypt(userKey, cacheKey, encryptedString, protection)
                }
            } else {
                memoryCache[cacheKey] = storedValue.toCacheValue()
            }
        }

        // Second pass: decrypt PLAIN_TEXT-memory entries concurrently. Failed decrypts
        // are silently dropped from the cache (existing behaviour); cancellation propagates.
        if (pendingDecrypts.isNotEmpty()) {
            val gate = Semaphore(maxParallelEncrypts)
            coroutineScope {
                pendingDecrypts.map { p ->
                    async {
                        gate.withPermit {
                            try {
                                val alias = aliasForRead(p.userKey, p.protection)
                                val plain = engine.decryptSuspend(alias, b64Decode(p.ciphertextB64))
                                memoryCache[p.cacheKey] = plain.decodeToString()
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

        // Sync encMetaMap: drop entries that no longer have on-disk metadata
        // (and aren't dirty). Adds/updates already happened in the pre-pass
        // before the second-pass decrypt.
        for (userKey in encMetaMap.snapshot().keys) {
            if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKey(userKey)) {
                encMetaMap.remove(userKey)
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
        // Fast path: if this instance has never seen an encrypted entry (neither written
        // nor loaded from disk), the value is definitely plaintext — skip the map lookups
        // entirely. Single atomic-flag read replaces two `ConcurrentHashMap` operations.
        if (!hasAnyEncryptedKey.get()) return null

        // 2.0 metadata is authoritative — including the "NONE" literal meaning
        // explicitly unencrypted. Only fall through to the legacy heuristic when
        // no 2.0 metadata exists at all (purely 1.x-written keys loaded from disk
        // and never re-written through 2.0).
        val meta = protectionMap[key]
        if (meta != null) return KeySafeMetadataManager.parseProtection(meta)
        return if (memoryCache.containsKey(legacyEncryptedRawKey(key))) KSafeProtection.DEFAULT else null
    }

    // ============================================================
    // Write coalescer
    // ============================================================

    private fun startWriteConsumer() {
        writeScope.launch {
            val batch = mutableListOf<PendingWrite>()
            while (isActive) {
                // Suspend until at least one write arrives.
                batch.add(writeChannel.receive())

                // Phase 1 — greedy drain. Pull every write that's already sitting
                // in the channel without waiting. This is what lets a burst of
                // 1000 `putDirect` (or concurrent suspend `put`) calls coalesce
                // into one `applyBatch` transaction instead of `maxBatchSize`-
                // capped chunks: by the time the consumer reaches this point the
                // channel may already hold hundreds of writes, and we take them
                // all in O(1) per write.
                while (batch.size < maxBatchSize) {
                    val next = writeChannel.tryReceive().getOrNull() ?: break
                    batch.add(next)
                }

                // Phase 2 — optional 16 ms wait window. Only applies when the
                // batch has no awaiters: the window exists to coalesce sparse
                // fire-and-forget `putDirect` calls that arrive over the next
                // frame. If even one caller is awaiting their commit (suspend
                // `put` / `delete`), they want it ASAP, so we skip the window
                // and process whatever we already have. This is what makes a
                // single sequential `ksafe.put(...)` complete in ~one batch
                // round-trip instead of `~window + round-trip`.
                if (batch.size < maxBatchSize && batch.none { it.completion != null }) {
                    val windowStart = TimeSource.Monotonic.markNow()
                    while (batch.size < maxBatchSize) {
                        val remaining = writeCoalesceWindowMs - windowStart.elapsedNow().inWholeMilliseconds
                        if (remaining <= 0) break
                        val next = withTimeoutOrNull(remaining) { writeChannel.receive() } ?: break
                        batch.add(next)
                        // Once a waiter arrives, exit the window early so they
                        // don't sit unnecessarily.
                        if (next.completion != null) break
                    }
                }

                runCatching { processBatch(batch) }
                    .onFailure { e ->
                        if (e is CancellationException) throw e
                        // Awaiting callers (suspend put/delete) were already
                        // notified via completeExceptionally inside processBatch.
                        // This log surfaces the failure for fire-and-forget
                        // putDirect callers who have no Deferred to listen on.
                        // Include the exception type so a bare message like
                        // "sun/misc/Unsafe" is recognisable as a
                        // NoClassDefFoundError (see issue #32) instead of
                        // looking like a stray log line.
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

        // Cache awaiters once — same set is used to complete or fail at the end.
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
        val aliasesToDelete = mutableListOf<String>()
        val encryptedCiphertext = mutableMapOf<String, ByteArray>()

        // Coalesce to the LAST write per userKey. A put and a delete are each
        // absolute (every op fully determines a key's final state), so applying
        // a 16ms window in order is equivalent to applying only the last op per
        // key. That equivalence is also the fix for the delete+put race: a
        // delete and a put for the same key in one batch must NOT both take
        // effect. The old code emitted the put's ciphertext AND then ran the
        // delete's `engine.deleteKey(keyAlias)` afterward, instantly orphaning a
        // just-written HARDWARE_ISOLATED entry (its per-entry key was deleted).
        // Letting the final op win prevents that.
        val finalByKey = LinkedHashMap<String, PendingWrite>()
        for (op in batch) finalByKey[op.userKey] = op

        // Only keys whose FINAL op is an encrypted write need encrypting.
        val toEncrypt = finalByKey.values.filterIsInstance<PendingWrite.Encrypted>()

        // Encrypt the deduped set concurrently. v2 envelope routes DEFAULT
        // entries through the datastore's master alias (one of two — locked or
        // unlocked — chosen by `requireUnlockedDevice`); HARDWARE_ISOLATED
        // entries keep their per-entry alias. The per-alias locks inside
        // engines never contend across distinct identifiers, so DEFAULT writes
        // serialise on the master alias's lock (cheap, in-process) while
        // HARDWARE_ISOLATED encrypts pipeline freely.
        if (toEncrypt.isNotEmpty()) {
            val gate = Semaphore(maxParallelEncrypts)
            coroutineScope {
                toEncrypt.map { op ->
                    async {
                        gate.withPermit {
                            val alias = aliasForWrite(op.userKey, op.protection, op.requireUnlockedDevice)
                            op.userKey to engine.encryptSuspend(
                                identifier = alias,
                                data = op.jsonString.encodeToByteArray(),
                                hardwareIsolated = op.protection == KSafeProtection.HARDWARE_ISOLATED,
                                requireUnlockedDevice = op.requireUnlockedDevice,
                            )
                        }
                    }
                }.awaitAll().forEach { (k, ct) -> encryptedCiphertext[k] = ct }
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

        // For ciphertext-at-rest policies: swap plaintext → ciphertext in cache.
        // CAS guard prevents overwriting a newer `putDirect` issued mid-batch.
        // The plaintextCache (populated optimistically by the put path) keeps the
        // plaintext available for fast reads under ENCRYPTED_WITH_TIMED_CACHE and
        // LAZY_PLAIN_TEXT.
        if (cacheHoldsCiphertext) {
            for (op in finalByKey.values) {
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
                            val plainBytes = engine.decryptSuspend(alias, b64Decode(enc))
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
            encMetaMap[key] = EncMeta(
                envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_LATEST,
                requireUnlockedDevice = requireUnlockedDevice,
            )
            hasAnyEncryptedKey.set(true)

            if (usesPlaintextSideCache) {
                plaintextCache[rawCacheKey] = CachedPlaintext(jsonString, plaintextExpiry())
            }

            writeChannel.trySend(
                PendingWrite.Encrypted(
                    userKey = key,
                    rawCacheKey = rawCacheKey,
                    jsonString = jsonString,
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
            encMetaMap.remove(key)

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
        // Optimistic in-memory state (matches `putEncryptedDirect`): subsequent
        // reads from any thread see the new value the instant this returns.
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
        if (usesPlaintextSideCache) {
            plaintextCache[rawCacheKey] = CachedPlaintext(jsonString, plaintextExpiry())
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
                completion = deferred,
            )
        )
        deferred.await()
    }

    private suspend fun putPlainSuspend(key: String, value: Any?, serializer: KSerializer<*>) {
        // Optimistic in-memory state (matches `putPlainDirect`).
        dirtyKeys.add(key)
        protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(null)
        encMetaMap.remove(key)

        val toCache: Any = if (value == null) NULL_SENTINEL
        else when (value) {
            is Boolean, is Int, is Long, is Float, is Double, is String -> value
            else -> jsonEncode(json, serializer, value)
        }
        memoryCache[key] = toCache

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
                completion = deferred,
            )
        )
        deferred.await()
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
        encMetaMap.remove(key)
        writeChannel.trySend(PendingWrite.Delete(userKey = key, rawCacheKey = rawKey))
    }

    suspend fun delete(key: String) {
        // Optimistic in-memory cleanup (matches `deleteDirect`).
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
                completion = deferred,
            )
        )
        deferred.await()
    }

    suspend fun clearAll() {
        // The per-entry key deletion below reads protectionMap to learn which
        // keys exist, so the cache must be populated first. Without this, a
        // clearAll() on a lazyLoad instance — or one called before the first
        // snapshot has populated the map — sees an empty protectionMap and
        // silently skips deleting per-entry engine keys, leaking them on JVM
        // (OS vault) and web (IndexedDB) exactly as before this guard existed.
        ensureCacheReadySuspend()
        // Delete per-entry engine keys BEFORE clearing protectionMap (which is
        // what tells us which keys exist). This covers HARDWARE_ISOLATED v2
        // entries (per-entry alias) and ALL legacy v1 entries (which used a
        // per-entry key even for DEFAULT). For v2 DEFAULT entries — which share
        // the master key — `keyAlias(userKey)` has no entry, so the delete is a
        // harmless no-op. Without this, web (IndexedDB) and JVM (OS vault) leak
        // these keys across clearAll() cycles: unlike Android/Apple they have no
        // startup orphan sweep for the engine's own keys, and after the storage
        // is cleared there is nothing left to cross-reference. Best-effort.
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

    fun getKeyInfo(key: String): KSafeKeyInfo? {
        ensureCacheReadyBlocking()
        val hasEncrypted = memoryCache.containsKey(legacyEncryptedRawKey(key))
        val hasPlain = memoryCache.containsKey(key)
        if (!hasEncrypted && !hasPlain) return null
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

            if (cacheHoldsCiphertext) {
                if (usesPlaintextSideCache) {
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
                        val plainBytes = engine.decrypt(aliasForRead(key, protection), b64Decode(encryptedString))
                        val candidate = plainBytes.decodeToString()
                        deserialized = if (candidate == NULL_SENTINEL) null
                        else jsonDecode(json, serializer, candidate)
                        success = true
                        if (usesPlaintextSideCache) {
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
        // KSafe's OWN definitive results — "key absent" and "vault unavailable /
        // degraded" — are never transient-retryable, even when the alias / file
        // name happens to contain a word like "keystore". Exclude them first, so a
        // store named e.g. "keystore" doesn't get its missing-key (or degraded)
        // reads misclassified as a retryable platform hiccup, which would throw
        // instead of returning the caller's default.
        if (msg.contains("No encryption key found", ignoreCase = true) ||
            msg.contains("key not found", ignoreCase = true) ||
            msg.contains("vault unavailable", ignoreCase = true)
        ) {
            return false
        }
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
