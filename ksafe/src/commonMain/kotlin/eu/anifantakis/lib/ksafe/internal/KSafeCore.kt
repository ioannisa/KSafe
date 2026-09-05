package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.KSafeEncryptedProtection
import eu.anifantakis.lib.ksafe.KSafeKeyInfo
import eu.anifantakis.lib.ksafe.KSafeKeyRotationPolicy
import eu.anifantakis.lib.ksafe.KSafeKeyStorage
import eu.anifantakis.lib.ksafe.KSafeMemoryPolicy
import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.KSafeProtectionLevel
import eu.anifantakis.lib.ksafe.KSafeRotationResult
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import eu.anifantakis.lib.ksafe.KSafeBase64
import eu.anifantakis.lib.ksafe.internal.coreparts.aliasForRawMeta
import eu.anifantakis.lib.ksafe.internal.coreparts.capturePerEntryAliasChange
import eu.anifantakis.lib.ksafe.internal.coreparts.convertStoredValue
import eu.anifantakis.lib.ksafe.internal.coreparts.decryptEntry
import eu.anifantakis.lib.ksafe.internal.coreparts.drainRemaining
import eu.anifantakis.lib.ksafe.internal.coreparts.encMetaForWrite
import eu.anifantakis.lib.ksafe.internal.coreparts.encodePlainValue
import eu.anifantakis.lib.ksafe.internal.coreparts.ensureCacheReadyBlocking
import eu.anifantakis.lib.ksafe.internal.coreparts.isRotationRetryable
import eu.anifantakis.lib.ksafe.internal.coreparts.isTransientDecryptFailure
import eu.anifantakis.lib.ksafe.internal.coreparts.ksafeEpochMillis
import eu.anifantakis.lib.ksafe.internal.coreparts.legacyProtectionRawKey
import eu.anifantakis.lib.ksafe.internal.coreparts.lockedDecryptRetryBackoffMs
import eu.anifantakis.lib.ksafe.internal.coreparts.metaRawKey
import eu.anifantakis.lib.ksafe.internal.coreparts.nullOrDefault
import eu.anifantakis.lib.ksafe.internal.coreparts.prewarmMasterKeys
import eu.anifantakis.lib.ksafe.internal.coreparts.putEncryptedSuspend
import eu.anifantakis.lib.ksafe.internal.coreparts.putPlainSuspend
import eu.anifantakis.lib.ksafe.internal.coreparts.raiseToAtLeast
import eu.anifantakis.lib.ksafe.internal.coreparts.resolveFromCache
import eu.anifantakis.lib.ksafe.internal.coreparts.retryingTransientReads
import eu.anifantakis.lib.ksafe.internal.coreparts.stageDelete
import eu.anifantakis.lib.ksafe.internal.coreparts.stagePlainWrite
import eu.anifantakis.lib.ksafe.internal.coreparts.startBackgroundCollector
import eu.anifantakis.lib.ksafe.internal.coreparts.startWriteConsumer
import eu.anifantakis.lib.ksafe.internal.coreparts.strictAliasVariantFor
import eu.anifantakis.lib.ksafe.internal.coreparts.triggerLazyStartupCleanupOnce
import eu.anifantakis.lib.ksafe.internal.coreparts.updateCacheOnce
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.retryWhen
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlin.concurrent.Volatile
import kotlin.time.ComparableTimeMark
import kotlin.time.Duration
import kotlin.time.TimeSource

/** Marker that makes a transient decrypt failure resubscribe instead of terminating the flow. */
private class TransientDecryptRetry(cause: Throwable) : Exception(cause)

/**
 * Platform-independent orchestration engine between the public [KSafe] API and the
 * platform backends ([KSafePlatformStorage], [KSafeEncryption]). Owns the hot cache,
 * write coalescer, protection metadata, background preload, and orphan cleanup.
 */
@PublishedApi
internal class KSafeCore(
    @PublishedApi internal val storage: KSafePlatformStorage,
    /**
     * Stable store identity bound into the v3 authenticated envelope, supplied by the platform
     * factory: the full absolute DataStore path on Android and Apple, the absolute
     * File(resolvedBaseDir, baseFileName) path on JVM, and the normalized fileName ("" for the
     * default store) on Web. Blocks cross-store ciphertext transplantation even where key material
     * coincidentally coincides. Deliberately NOT the appNamespace: that may legitimately change
     * across upgrades (the supported add-a-namespace-later migration), and its protection is the
     * key separation it already enforces.
     */
    @PublishedApi internal val storeIdentity: String = "",
    /**
     * The v3 AAD identity entries carry when canonicalization was unavailable (the raw,
     * non-canonical absolute-path spelling). Blank or equal to [storeIdentity] for the common case.
     * When it differs — a custom baseDir reached under a relative/symlinked/`..` spelling, or a
     * session where resolving the canonical path failed and the caller degraded to the raw one —
     * v3 entries bound to that identity are retried under it before falling to defaults, and a
     * subsequent write/rotation re-binds them to the canonical [storeIdentity].
     */
    @PublishedApi internal val fallbackStoreIdentity: String = "",
    /**
     * The store's key-namespace token (the normalized fileName; null for the default store).
     * Folded into the fingerprint of generation-suffixed per-entry aliases
     * ([perEntryAliasWithGeneration]) so rotated aliases are store-distinct and can't be
     * shadowed by another key's bare alias.
     */
    @PublishedApi internal val keyNamespace: String? = null,
    /**
     * Serializes batch commits (writes, clearAll, rotation CAS + sweeps) ACROSS same-file
     * instances: the platform backends pass one mutex per physical store, so two live cores
     * on one file can't interleave inside each other's snapshot→commit sequences. Single
     * instances keep the private default (their one consumer already serializes).
     */
    @PublishedApi internal val commitMutex: Mutex = Mutex(),
    /** Deferred so the platform shell can swap in a test engine after wiring. */
    engineProvider: () -> KSafeEncryption,
    private val config: KSafeConfig,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy,
    @PublishedApi internal val plaintextCacheTtl: Duration,
    /**
     * Storage tier reported by `getKeyInfo`; platform shells inspect StrongBox / Secure Enclave.
     * `engineAlias` is the alias the entry's recorded envelope decrypts under (null for plain
     * entries), so shells that can inspect the live key report its actual custody rather than
     * inferring from the requested tier.
     */
    private val resolveKeyStorage: (userKey: String, protection: KSafeProtection?, engineAlias: String?) -> KSafeKeyStorage,
    /** Per-key [KSafeProtectionLevel] reported by `getKeyInfo`; platform-specific, same
     *  `engineAlias` contract as [resolveKeyStorage]. */
    private val resolveKeyLevel: (userKey: String, protection: KSafeProtection?, engineAlias: String?) -> KSafeProtectionLevel,
    /** Per-platform migration hook run once before orphan cleanup (iOS accessibility tiers). */
    internal val migrateAccessPolicy: suspend (isUserKeyDirty: (String) -> Boolean) -> Unit = {},
    internal val lazyLoad: Boolean = false,
    /** Builds the per-entry Keystore/Keychain alias for a user key. */
    @PublishedApi internal val keyAlias: (userKey: String) -> String,
    /**
     * Master alias for the datastore, one per unlock policy (relaxed/strict). Holds the
     * AES key shared by v2 DEFAULT entries; HARDWARE_ISOLATED entries use per-entry keys.
     */
    @PublishedApi internal val masterAlias: (requireUnlockedDevice: Boolean) -> String,
    /** Prefix recognising legacy-format encrypted entries on disk (iOS overrides per filename). */
    internal val legacyEncryptedPrefix: String = KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX,
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
     * (v2 + DEFAULT routes to the master alias picked by `requireUnlockedDevice`, and
     * [keyGeneration] picks the alias generation — 1 is the un-suffixed base every
     * pre-rotation entry uses). Plain entries are never present.
     */
    @PublishedApi
    internal data class EncMeta(
        val envelopeVersion: Int,
        val requireUnlockedDevice: Boolean,
        val keyGeneration: Int = 1,
        /**
         * `true` when the entry's per-entry key lives under the strict alias variant
         * ([strictPerEntryAlias]). 3.0.0+ strict `HARDWARE_ISOLATED` writes set it; entries
         * written by released versions (or relaxed ones) stay `false` and keep decrypting
         * under the bare per-entry alias.
         */
        val strictAliasVariant: Boolean = false,
    )

    @PublishedApi
    internal val encMetaMap = KSafeConcurrentMap<EncMeta>()

    /**
     * The key generation new writes encrypt under. 1 until the store is rotated; bumped by
     * key rotation and kept in sync from the persisted [KeySafeMetadataManager.KEYGEN_RAW_KEY]
     * entry on every snapshot merge (so a co-existing instance's rotation propagates here).
     */
    @PublishedApi
    internal val currentKeyGeneration = KSafeAtomicInt(1)

    /**
     * Whether [currentKeyGeneration] has been reconciled against SOME persisted snapshot (a
     * cache merge, or the write consumer's first-batch read). Until then the local value is
     * the constructor default `1`, NOT the store's authority — a cold/lazy instance's first
     * write must not silently regress a rotated store's entries to generation 1 (dropping
     * the v3 authenticated envelope). The write consumer performs a one-shot disk read when
     * this is still false, keeping `putDirect` itself fire-and-forget.
     */
    internal val keyGenerationReconciled = KSafeAtomicFlag(false)

    /**
     * Bumped as [performClearAll]'s first action, and on every sibling core once the store is
     * wiped. Lets an unserialized cache merge (initial
     * lazy load, rollback re-merge, collector emission) detect that a wipe landed after its
     * snapshot was taken and redo itself, instead of republishing pre-clear secrets into RAM.
     * Also captured by [rotateKeys] into each [PendingWrite.Rotate]: a wipe invalidates the
     * pass's captured target generation, and every not-yet-committed entry re-encrypt must
     * then be skipped instead of stamping the stale generation onto post-clear entries.
     */
    internal val clearEpoch = KSafeAtomicInt(0)

    @PublishedApi
    internal class CachedPlaintext(val value: String, val expiresAt: ComparableTimeMark)

    @PublishedApi
    internal val plaintextCache = KSafeConcurrentMap<CachedPlaintext>()

    /**
     * Latest write's identity token per user key, claimed before any optimistic mutation.
     * A failed write may only roll back state it still owns — never state a newer
     * in-flight write to the same key has since claimed. Not wiped by clearAll.
     */
    internal val writeOwners = KSafeConcurrentMap<Any>()

    /** Test-only seam invoked inside the post-commit repair; always `null` in production. */
    @PublishedApi
    internal var postCommitRepairHook: ((String) -> Unit)? = null

    /** Test-only seam fired with a batch's keys after applyBatch; null in production. Runs under commitMutex: never call a suspend write from it. */
    internal var postApplyBatchHook: ((Set<String>) -> Unit)? = null

    /** `true` when the primary [memoryCache] holds Base64 ciphertext at rest. */
    internal val cacheHoldsCiphertext: Boolean =
        memoryPolicy == KSafeMemoryPolicy.ENCRYPTED ||
            memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE ||
            memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT

    /** `true` for policies with the secondary [plaintextCache] (TTL-bounded or permanent). */
    internal val usesPlaintextSideCache: Boolean =
        memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE ||
            memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT

    /** Side-cache freshness: never expires under LAZY_PLAIN_TEXT, TTL-bounded otherwise. */
    internal fun plaintextStillValid(cached: CachedPlaintext): Boolean =
        memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT ||
            TimeSource.Monotonic.markNow() < cached.expiresAt

    internal fun plaintextExpiry(): ComparableTimeMark =
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

    internal val writeScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    internal val collectorScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    /** Logical write queue — encryption happens inside the consumer, not on UI. */
    internal val writeChannel = Channel<PendingWrite>(Channel.UNLIMITED)

    internal val writeCoalesceWindowMs = 16L   // ~1 frame at 60 fps
    internal val maxBatchSize = 200

    /**
     * Caps concurrent encrypt/decrypt calls: overlapping keystore IPC pipelines well,
     * but unbounded fan-out floods Binder / Keychain and over-subscribes the dispatcher.
     */
    internal val maxParallelEncrypts = 8

    /** Shape shared by the ops the consumer's encrypt phase processes (user writes + rotations). */
    internal interface EncryptingWrite {
        val userKey: String
        val jsonString: String
        val protection: KSafeProtection
        val requireUnlockedDevice: Boolean
        val keyGeneration: Int
    }

    internal sealed class PendingWrite {
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

        /**
         * Failure notification for fire-and-forget callers: with [completion] null, a wrapper
         * holding an optimistic value (e.g. asMutableStateFlow) otherwise gets no signal that
         * its value never became durable. Invoked after the optimistic rollback, outside
         * locks, exceptions swallowed; not invoked on close/cancel drains (close terminality
         * is documented). Null everywhere else.
         */
        open val onWriteFailed: ((Throwable) -> Unit)? get() = null

        data class Plain(
            override val userKey: String,
            override val rawCacheKey: String,
            /** A primitive, the null sentinel, or pre-encoded JSON for complex types. */
            val value: Any,
            override val writeToken: Any,
            /**
             * The overwritten entry's recorded generation when it provably owned a per-entry
             * engine alias (HARDWARE_ISOLATED or legacy pre-v2); 0 otherwise. Captured before
             * the optimistic map wipe, like [Delete.keyGeneration]: without it an
             * encrypted→plain overwrite forgets the old platform key ever existed, leaving it
             * live for historical ciphertext copies and invisible to every later clearAll.
             */
            val supersededPerEntryGeneration: Int = 0,
            /** Whether that superseded key lived under the strict alias variant; see [Delete.usedStrictAlias]. */
            val supersededStrictAlias: Boolean = false,
            override val completion: CompletableDeferred<Unit>? = null,
            override val onWriteFailed: ((Throwable) -> Unit)? = null,
        ) : PendingWrite()

        data class Encrypted(
            override val userKey: String,
            override val rawCacheKey: String,
            override val jsonString: String,
            override val protection: KSafeProtection,
            override val requireUnlockedDevice: Boolean,
            override val writeToken: Any,
            /**
             * Captured at enqueue so the committed metadata, the encrypt alias, and the
             * caller's optimistic [EncMeta] all name the same key — a rotation landing
             * between enqueue and commit must not split them.
             */
            override val keyGeneration: Int = 1,
            /**
             * Per-entry aliases this write's entry PREVIOUSLY resolved to, when the write
             * moves it to a different alias (an unlock-policy transition, or a legacy strict
             * entry migrating to the strict alias variant). Captured at enqueue, BEFORE the
             * optimistic [EncMeta] overwrite — by the time the consumer runs, the map
             * already shows the new routing, so the transition is invisible there. A list so
             * coalescing can accumulate every displaced write's capture (a tighten displaced
             * by a further transition contributes its own superseded alias). The old aliases
             * are reclaimed AFTER the commit through the guarded reclaim path; they are
             * never touched before the write's own encrypt and commit succeed, so any
             * failure leaves the previous value fully decryptable.
             */
            val supersededAliases: List<String> = emptyList(),
            override val completion: CompletableDeferred<Unit>? = null,
            override val onWriteFailed: ((Throwable) -> Unit)? = null,
        ) : PendingWrite(), EncryptingWrite

        /**
         * One entry's key rotation: re-encrypts an already-decrypted payload under
         * [keyGeneration] (the NEW generation). Never claims [writeOwners] and never touches
         * optimistic state — it is not a user write. Committed ONLY if the entry's stored
         * ciphertext still equals [expectedOldCiphertext] at commit time (CAS inside the
         * serialized consumer), so a racing user write always wins and is never clobbered
         * with a re-encrypt of the older value.
         */
        data class Rotate(
            override val userKey: String,
            override val rawCacheKey: String,
            override val jsonString: String,
            override val protection: KSafeProtection,
            override val requireUnlockedDevice: Boolean,
            override val keyGeneration: Int,
            val expectedOldCiphertext: String,
            /** Superseded per-entry alias to delete after commit; null when it is a shared master (swept by the orchestrator). */
            val oldAliasToDelete: String?,
            /**
             * [clearEpoch] at the rotation pass's start. A clearAll landing between the pass's
             * generation bump and this entry's commit resets the store (and its generation) —
             * committing would stamp the stale target generation onto a post-clear store, so
             * the consumer skips the op when the epoch (or the store generation) has moved.
             */
            val expectedClearEpoch: Int,
            /**
             * The key's [writeOwners] token at rotation issue (null when never written this
             * session). Plaintext-policy caches can't prove "entry untouched" via the
             * ciphertext CAS, so the post-commit meta bump anchors on this instead: an
             * unchanged token means no user write claimed the key since the rotation read it.
             */
            val ownerTokenAtIssue: Any? = null,
            /** Set to true by the consumer iff the CAS passed and the rotation committed. */
            val applied: KSafeAtomicFlag = KSafeAtomicFlag(false),
            override val completion: CompletableDeferred<Unit>,
        ) : PendingWrite(), EncryptingWrite {
            override val writeToken: Any = Any() // unregistered — rollback machinery ignores rotations
        }

        /**
         * Persists a new store-level key generation (serialized with all writes, so every
         * write ordered after it in the channel commits against the bumped state).
         * [timestampMillis] is the generation's birth — the age the MaxAge policy measures.
         */
        data class SetKeyGeneration(
            val generation: Int,
            val timestampMillis: Long,
            /**
             * True only for the generation bump that starts a rotation. Persisted with the
             * bump, before any entry is touched, so a later instance can resume this exact
             * generation after process death instead of incorrectly advancing to another one.
             */
            val rotationInProgress: Boolean = false,
            /**
             * True only when the next KSafe instance claims a normally-completed generation's
             * persisted retry budget. The consumer changes `r:0,rp:N` to `r:1,rp:N-1` only
             * while that exact state is still durable; decrement-before-work makes crashes
             * unable to refill the budget, while the CAS lets same-file instances race without
             * running duplicate work.
             */
            val claimPendingRetry: Boolean = false,
            /** Set by the consumer iff this lifecycle transition was durably applied. */
            val applied: KSafeAtomicFlag = KSafeAtomicFlag(false),
            override val completion: CompletableDeferred<Unit>,
        ) : PendingWrite() {
            override val userKey: String get() = KeySafeMetadataManager.KEYGEN_RAW_KEY
            override val rawCacheKey: String get() = KeySafeMetadataManager.KEYGEN_RAW_KEY
            override val writeToken: Any get() = this // never rolled back per-key
        }

        /**
         * Changes the durable lifecycle marker from in-progress (`r:1`) to completed (`r:0`)
         * after every entry commit and the superseded-master sweep have completed. The
         * consumer applies it only while the persisted store is still at [generation], so a
         * stale pass can never acknowledge a newer rotation as completed.
         */
        data class CompleteKeyRotation(
            val generation: Int,
            /**
             * Persisted only when the pass returned normally with retryable (`skipped`)
             * entries and another automatic attempt remains. Null means no pending retry.
             */
            val retryAttemptsRemaining: Int? = null,
            override val completion: CompletableDeferred<Unit>,
        ) : PendingWrite() {
            override val userKey: String get() = KeySafeMetadataManager.KEYGEN_RAW_KEY
            override val rawCacheKey: String get() = KeySafeMetadataManager.KEYGEN_RAW_KEY
            override val writeToken: Any get() = this // never rolled back per-key
        }

        /**
         * Deletes superseded MASTER generations (below [newGeneration]) that no persisted
         * entry references. MUST run on the consumer: serialized with every write, so no
         * batch can be lazily minting/encrypting under an old master while this deletes it —
         * the unserialized variant could delete a key between a concurrent batch's mint and
         * its commit, making an acknowledged write unreadable after restart. A stale-
         * generation write processed AFTER this sweep self-heals (its encrypt lazily mints a
         * fresh key under the old alias and its ciphertext decrypts with it).
         */
        data class SweepSupersededMasters(
            val newGeneration: Int,
            override val completion: CompletableDeferred<Unit>,
        ) : PendingWrite() {
            override val userKey: String get() = "__ksafe_sweep_masters__"

            // Must equal [userKey]: the coalescer keys ops by userKey and the batch boundary
            // recognises them by rawCacheKey, so two literals would let this op key against itself
            // inconsistently.
            override val rawCacheKey: String get() = userKey
            override val writeToken: Any get() = this // never rolled back per-key
        }

        data class Delete(
            override val userKey: String,
            override val rawCacheKey: String,
            override val writeToken: Any,
            /**
             * The entry's recorded generation, captured BEFORE the optimistic [encMetaMap]
             * removal — by commit time the map no longer knows which alias the entry used.
             */
            val keyGeneration: Int = 1,
            /**
             * Whether the entry's recorded state proved it used a per-entry engine alias
             * (HARDWARE_ISOLATED, or a legacy pre-v2 envelope), captured like [keyGeneration].
             * Gates the engine-key sweep: deleting the alias of a plain, master-riding, or
             * absent entry is not a harmless no-op — a dotted user key's alias can be
             * byte-identical to another store's live key.
             */
            val usedPerEntryAlias: Boolean = false,
            /**
             * Whether the entry's key lived under the strict alias variant, captured like
             * [keyGeneration]. Widens the sweep past the prune that asks only what a new user
             * write can reach — see [perEntryAliasesThrough].
             */
            val usedStrictAlias: Boolean = false,
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
            override val rawCacheKey: String get() = userKey
            override val writeToken: Any get() = this // never rolled back per-key
        }
    }

    @PublishedApi
    internal fun valueRawKey(key: String): String = KeySafeMetadataManager.valueRawKey(key)

    @PublishedApi
    internal fun legacyEncryptedRawKey(key: String): String = legacyEncryptedKeyFor(key)

    @PublishedApi
    internal fun defaultEncryptedMode(): KSafeWriteMode =
        KSafeWriteMode.Encrypted(requireUnlockedDevice = config.requireUnlockedDevice)

    /**
     * Write alias: DEFAULT routes to the master alias for the unlock policy;
     * HARDWARE_ISOLATED uses the per-entry alias — the strict variant when
     * [requireUnlockedDevice] is set (3.0.0+), so a relaxed→strict rewrite never has to
     * destroy the relaxed key before its own encrypt succeeds: the strict key is minted
     * under a fresh alias, the commit lands, and only then is the old alias reclaimed.
     * [keyGeneration] must be the generation recorded in the same write's metadata, so
     * the entry always names the alias that decrypts it.
     */
    @PublishedApi
    internal fun aliasForWrite(
        userKey: String,
        protection: KSafeProtection,
        requireUnlockedDevice: Boolean,
        keyGeneration: Int = 1,
    ): String =
        if (protection == KSafeProtection.DEFAULT) {
            aliasWithGeneration(masterAlias(requireUnlockedDevice), keyGeneration)
        } else if (strictAliasVariantFor(protection, requireUnlockedDevice)) {
            strictPerEntryAlias(userKey, keyGeneration)
        } else {
            perEntryAlias(userKey, keyGeneration)
        }

    /**
     * Whether a new USER write in this store can land on the strict per-entry alias variant.
     * Derived from [modeTransformer], the single place a platform vetoes an unlock policy: web
     * strips `requireUnlockedDevice` before the entry's routing record is built (its strict read
     * path needs a blocking decrypt async-only WebCrypto cannot serve).
     *
     * Not the whole answer to "can this store hold a strict key": rotation bypasses
     * [modeTransformer] and takes the policy from the entry's own metadata, so a legacy web entry
     * written before that veto rotates into one. Each sweep therefore ORs this with the entry's
     * recorded `strictAliasVariant` — see `perEntryAliasesThrough`.
     *
     * Used ONLY to prune the delete/clearAll alias sweeps, where enumerating an unreachable
     * spelling costs a pointless engine delete per generation (on web, a permanent `localStorage`
     * tombstone against the origin's shared quota). Never consulted by the read or write routing,
     * where dropping a spelling would strand data under an alias nothing resolves to.
     */
    internal val strictAliasVariantReachable: Boolean =
        (
            modeTransformer(
                KSafeWriteMode.Encrypted(
                    protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
                    requireUnlockedDevice = true,
                )
            ) as? KSafeWriteMode.Encrypted
            )?.requireUnlockedDevice == true

    /** Per-entry alias for [userKey] at [generation]; see [perEntryAliasWithGeneration]. */
    @PublishedApi
    internal fun perEntryAlias(userKey: String, generation: Int): String =
        perEntryAliasWithGeneration(keyAlias(userKey), generation, keyNamespace, userKey)

    /** Strict per-entry alias variant; see [strictPerEntryAliasWithGeneration]. */
    @PublishedApi
    internal fun strictPerEntryAlias(userKey: String, generation: Int): String =
        strictPerEntryAliasWithGeneration(keyAlias(userKey), generation, keyNamespace, userKey)

    /**
     * AAD for reading [userKey] under its RECORDED envelope, built from the same [encMetaMap]
     * fields the read path routes on; see [aadForEnvelope].
     */
    @PublishedApi
    internal fun aadForRead(userKey: String, protection: KSafeProtection?): ByteArray? {
        val em = encMetaMap[userKey] ?: return null
        return aadForEnvelope(
            storeIdentity, userKey, protection,
            em.requireUnlockedDevice, em.keyGeneration, em.envelopeVersion,
        )
    }

    /** True when the store was reached under a non-canonical path spelling, so v3 entries bound
     *  to the raw absolute-path identity need a decrypt fallback. */
    internal val hasFallbackIdentity: Boolean =
        fallbackStoreIdentity.isNotEmpty() && fallbackStoreIdentity != storeIdentity

    /**
     * Read alias from the entry's recorded envelope in [encMetaMap] — the safe per-entry
     * default when no metadata is loaded yet. The entry's own recorded generation picks the
     * alias generation, never the store's current one: a not-yet-rotated entry keeps decrypting
     * under the key it was written with. Routing itself lives in [aliasForRecordedMeta].
     */
    @PublishedApi
    internal fun aliasForRead(userKey: String, protection: KSafeProtection?): String =
        aliasForRawMeta(userKey, protection, encMetaMap[userKey])

    /** Guards the one-time startup cleanup (collector first emission or lazy first access). */
    internal val startupCleanupDone = KSafeAtomicFlag(false)
    internal val lazyStartupCleanupLaunched = KSafeAtomicFlag(false)

    /**
     * Runs rotation maintenance once per startup, on the background scope — never blocking
     * startup or reads. An interrupted pass is resumed at its already-persisted generation
     * regardless of [KSafeConfig.keyRotationPolicy]. A normally completed pass that left
     * retryable entries receives a bounded retry budget consumed one attempt per newly created
     * KSafe instance. If MaxAge is already due on that next run, its fresh rotation supersedes
     * the same-generation retry. The current instance never waits or loops after a normally
     * completed pass.
     */
    internal fun maybeScheduleKeyRotation() {
        val policy = config.keyRotationPolicy
        collectorScope.launch {
            var recoveringExistingGeneration = false
            var unsupportedPersistedState = false
            runCatching {
                val raw = (storage.snapshot()[KeySafeMetadataManager.KEYGEN_RAW_KEY] as? StoredValue.Text)?.value
                val lifecycle = KeySafeMetadataManager.parseKeyRotationLifecycle(raw)
                val hasLifecycle = KeySafeMetadataManager.hasKeyRotationLifecycle(raw)
                val retryAttempts =
                    KeySafeMetadataManager.parseKeyRotationRetryAttempts(raw)
                if (!KeySafeMetadataManager.hasSupportedKeyRotationRetryState(raw)) {
                    unsupportedPersistedState = true
                    error("KSafe: unsupported key-rotation retry marker; the store was left untouched")
                }
                if (KeySafeMetadataManager.isLegacy30KeyGenerationState(raw)) {
                    // KSafe 3.0.0 persisted generation + timestamp but had no lifecycle
                    // field. Absence is therefore proof of "old completed format", NEVER
                    // proof of a crash. Adopt it as r:0 and deliberately stop here: no
                    // resume, generation bump, entry rewrite, sweep, or same-launch MaxAge.
                    val adopted = CompletableDeferred<Unit>()
                    writeChannel.send(
                        PendingWrite.SetKeyGeneration(
                            generation = KeySafeMetadataManager.parseKeyGeneration(raw),
                            timestampMillis =
                                KeySafeMetadataManager.parseKeyGenerationTimestamp(raw)
                                    ?: ksafeEpochMillis(),
                            completion = adopted,
                        )
                    )
                    adopted.await()
                } else if (lifecycle == 1) {
                    recoveringExistingGeneration = true
                    val result = resumeInterruptedRotation()
                    if (result != null) {
                        println(
                            "KSafe: resumed interrupted key rotation at generation " +
                                "${result.keyGeneration} (rotated ${result.rotated}, " +
                                "skipped ${result.skipped}, failed ${result.failed})."
                        )
                    }
                } else if (
                    hasLifecycle &&
                    lifecycle == 0 &&
                    retryAttempts != null &&
                    retryAttempts > 0
                ) {
                    val now = ksafeEpochMillis()
                    val bornAt = KeySafeMetadataManager.parseKeyGenerationTimestamp(raw)
                    val maxAgeDue =
                        policy is KSafeKeyRotationPolicy.MaxAge &&
                            bornAt != null &&
                            now - bornAt >= policy.maxAge.inWholeMilliseconds
                    if (maxAgeDue) {
                        val result = rotateKeys()
                        println(
                            "KSafe: MaxAge key-rotation pass superseded pending retry -> " +
                                "generation ${result.keyGeneration} (rotated ${result.rotated}, " +
                                "skipped ${result.skipped}, failed ${result.failed})."
                        )
                    } else if (config.keyRotationRetryAttempts > 0) {
                        recoveringExistingGeneration = true
                        val result = retryPendingRotationAtStartup()
                        if (result != null) {
                            println(
                                "KSafe: retried incomplete key rotation at generation " +
                                    "${result.keyGeneration} (rotated ${result.rotated}, " +
                                    "skipped ${result.skipped}, failed ${result.failed})."
                            )
                        }
                    }
                } else if ((hasLifecycle && lifecycle == 0) || raw == null) {
                    if (policy !is KSafeKeyRotationPolicy.MaxAge) return@runCatching
                    val now = ksafeEpochMillis()
                    val bornAt = KeySafeMetadataManager.parseKeyGenerationTimestamp(raw)
                    if (bornAt == null) {
                        val stamped = CompletableDeferred<Unit>()
                        writeChannel.send(
                            PendingWrite.SetKeyGeneration(
                                currentKeyGeneration.get(), now, completion = stamped,
                            )
                        )
                        stamped.await()
                    } else if (now - bornAt >= policy.maxAge.inWholeMilliseconds) {
                        val result = rotateKeys()
                        println(
                            "KSafe: MaxAge key-rotation pass -> generation ${result.keyGeneration} " +
                                "(rotated ${result.rotated}, skipped ${result.skipped}, " +
                                "failed ${result.failed})."
                        )
                    }
                } else {
                    // An unknown future/corrupt lifecycle value is routing state, not a hint.
                    // Preserve it and fail closed instead of overwriting it as "completed".
                    unsupportedPersistedState = true
                    error(
                        "KSafe: unsupported key-rotation lifecycle marker r=$lifecycle; " +
                            "the store was left untouched"
                    )
                }
            }.onFailure {
                if (it is CancellationException) throw it
                // Both refusals below are permanent — every launch would fail identically,
                // so don't promise a retry that can never succeed.
                val exhausted =
                    !recoveringExistingGeneration &&
                        currentKeyGeneration.get() >= KeySafeMetadataManager.MAX_KEY_GENERATION
                ksafeLogWarning(
                    "KSafe: scheduled key rotation failed " +
                        "(${it::class.simpleName}: ${it.message}); " +
                        when {
                            unsupportedPersistedState ->
                                "the persisted rotation state is not one this build " +
                                    "understands — it is preserved untouched, and every " +
                                    "launch will refuse identically until it is repaired."
                            exhausted ->
                                "the key-generation counter has reached its maximum — " +
                                    "automatic rotation is now permanently a no-op for " +
                                    "this store."
                            else -> "it will retry on a later launch."
                        }
                )
            }
        }
    }

    /** True if [userKey] has an in-flight write under any raw-key form; reads the LIVE set. */
    internal fun isUserKeyDirty(userKey: String): Boolean =
        dirtyKeys.contains(valueRawKey(userKey)) ||
            dirtyKeys.contains(legacyEncryptedRawKey(userKey)) ||
            dirtyKeys.contains(userKey)

    /**
     * Merges an on-disk snapshot into the memory cache. Dirty (in-flight) keys
     * are skipped so optimistic `putDirect` values are never clobbered by a
     * stale DataStore emission.
     *
     * [epochAtSnapshot] must be read from [clearEpoch] BEFORE the snapshot was taken
     * (capture-then-snapshot; an after-read reintroduces the race): a merge whose snapshot
     * predates a concurrent [performClearAll] would republish wiped secrets into the caches
     * AFTER clearAll returned — under lazyLoad nothing ever evicts them again. When the epoch
     * moved mid-merge, the merge redoes itself from a fresh post-clear snapshot, whose empty
     * valid-key set evicts anything the stale pass resurrected.
     */
    @PublishedApi
    internal suspend fun updateCache(
        snapshot: Map<String, StoredValue>,
        epochAtSnapshot: Int = clearEpoch.get(),
    ) {
        var snap = snapshot
        var epoch = epochAtSnapshot
        var attempts = 0
        while (true) {
            updateCacheOnce(snap)
            // Bounded: each retry needs ANOTHER clearAll to land mid-merge; the collector
            // (eager mode) and the clear's own map wipe bound the residue if the cap trips.
            if (clearEpoch.get() == epoch || ++attempts >= 3) return
            epoch = clearEpoch.get()
            snap = storage.snapshot()
        }
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
     * A transient decrypt failure (locked device / busy Keystore) never reaches collectors as a
     * value or a throw: long-lived observers (viewModelScope / Recomposer) would crash and stop
     * observing. The flow resubscribes on a slow backoff instead, so an observer seeded while
     * the device was locked recovers on its own after unlock.
     */
    @PublishedApi
    internal fun getFlowRaw(
        key: String,
        defaultValue: Any?,
        serializer: KSerializer<*>,
    ): Flow<Any?> {
        return storage.snapshotFlow()
            // Resubscribe on a transient upstream read error (e.g. Jetpack DataStore emitting an
            // IOException into .data on a flaky read) exactly as the internal collector does —
            // otherwise a single transient storage error terminates the user's flow exceptionally:
            // the stateIn/observe scope's uncaught exception crashes on Android and freezes the
            // StateFlow forever, while the internal collector silently keeps getDirect fresh and
            // masks the cause. Placed BEFORE .map so only the storage read retries; per-emission
            // decrypt failures are handled by the slower retryWhen below.
            .retryingTransientReads { attempt, cause ->
                ksafeLogWarning(
                    "KSafe: getFlow snapshot read failed (attempt $attempt, " +
                        "${cause::class.simpleName}: ${cause.message}); resubscribing.",
                )
            }
            .map { snapshot ->
            val metaRaw = (snapshot[metaRawKey(key)] as? StoredValue.Text)?.value
                ?: (snapshot[legacyProtectionRawKey(key)] as? StoredValue.Text)?.value
            val protection = KeySafeMetadataManager.parseProtection(metaRaw)
                ?: when {
                    snapshot[legacyEncryptedRawKey(key)] != null -> KSafeProtection.DEFAULT
                    // Fail closed, matching getDirect/classifyStorageEntry: a canonical value slot
                    // with absent/tampered metadata holds ciphertext, so decrypt it rather than serve
                    // base64 via the plaintext arm. Guarded on the canonical slot so flat pre-2.0
                    // plaintext still resolves as plaintext.
                    snapshot[valueRawKey(key)] != null &&
                        KeySafeMetadataManager.isCanonicalValueEncrypted(metaRaw) -> KSafeProtection.DEFAULT
                    else -> null
                }

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
                            // Future-format entries fail closed to the default emission. The
                            // recorded unlock policy travels with the routing, so a strict entry
                            // bypasses the engine's in-memory key cache and the native store
                            // enforces the lock on every emission; on a locked device the strict
                            // decrypt throws transient and the flow resubscribes below.
                            val plainBytes = decryptEntry(
                                key, protection, KSafeBase64.decode(enc), encMetaFromRaw(metaRaw),
                            )
                            val rawString = plainBytes.decodeToString()
                            if (rawString == NULL_SENTINEL) nullOrDefault(defaultValue, serializer)
                            else jsonDecode(json, serializer, rawString)
                        } catch (e: Throwable) {
                            if (e is CancellationException) throw e
                            if (isTransientDecryptFailure(e)) throw TransientDecryptRetry(e)
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
            // cheap retry/distinctUntilChanged stay in the collector's context.
            .flowOn(decryptFlowContext)
            // Placed AFTER flowOn so a retry re-collects the WHOLE upstream: storage re-delivers
            // its current snapshot to the new collector, the only way to see the value without a write.
            .retryWhen { cause, attempt ->
                if (cause !is TransientDecryptRetry) return@retryWhen false
                if (attempt == 0L) {
                    ksafeLogWarning(
                        "KSafe: encrypted read of '$key' is temporarily unavailable " +
                            "(locked device / busy key store); the flow will retry.",
                    )
                }
                delay(lockedDecryptRetryBackoffMs(attempt))
                true
            }
            .distinctUntilChanged()
    }

    @PublishedApi
    internal fun putDirectRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) {
        putDirectRaw(key, value, mode, serializer, onWriteFailed = null)
    }

    /**
     * [putDirectRaw] plus a fire-and-forget failure notification (see
     * [PendingWrite.onWriteFailed]). A separate overload — not an optional
     * parameter on the original entry point — so its inline ABI stays untouched.
     */
    @PublishedApi
    internal fun putDirectRaw(
        key: String,
        value: Any?,
        mode: KSafeWriteMode,
        serializer: KSerializer<*>,
        onWriteFailed: ((Throwable) -> Unit)?,
    ) {
        KeySafeMetadataManager.requireWritableUserKey(key)
        @Suppress("NAME_SHADOWING") val mode = modeTransformer(mode)
        val protection = mode.toProtection()
        val requireUnlockedDevice = mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice

        if (protection != null) {
            // Serialize FIRST: a throwing serializer must leave no trace. Once the
            // ownership token, dirty flag, or routing metadata are touched, nothing
            // repairs them — rollback covers only ops that reached a batch, and the
            // cache merge skips dirty keys for the process lifetime.
            val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)

            // Claim rollback ownership before any optimistic mutation, so a
            // concurrently-failing older write for this key can no longer revert
            // the state set below.
            val writeToken = Any().also { writeOwners[key] = it }
            val rawCacheKey = legacyEncryptedRawKey(key)
            dirtyKeys.add(rawCacheKey)

            val writeKeyGeneration = currentKeyGeneration.get()
            val supersededAlias = capturePerEntryAliasChange(key, protection, requireUnlockedDevice, writeKeyGeneration)
            memoryCache[rawCacheKey] = jsonString
            protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(protection)
            encMetaMap[key] = encMetaForWrite(protection, requireUnlockedDevice, writeKeyGeneration)
            hasAnyEncryptedKey.set(true)

            // Plain→encrypted transition: a prior PLAINTEXT write of `key` populated the bare
            // `key` cache slot, while encrypted writes live under `rawCacheKey`
            // (= legacyEncryptedRawKey). The stale plain slot is otherwise never evicted — the
            // eviction sweep skips it because its dirty flag is deliberately never cleared on
            // success — so a plaintext copy of the now-encrypted secret would linger in RAM for
            // the process lifetime, defeating the ENCRYPTED memory policy. Evict it here, mirroring
            // deleteDirect. (rawCacheKey != key, so the freshly-set ciphertext slot is untouched.)
            memoryCache.remove(key)
            plaintextCache.remove(key)

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
                    keyGeneration = writeKeyGeneration,
                    supersededAliases = listOfNotNull(supersededAlias),
                    onWriteFailed = onWriteFailed,
                )
            )
        } else {
            // Serialize FIRST — same reasoning as the encrypted arm.
            val toStore = encodePlainValue(value, serializer)
            writeChannel.trySend(stagePlainWrite(key, toStore, onWriteFailed = onWriteFailed))
        }
    }

    @PublishedApi
    internal suspend fun putRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>) {
        KeySafeMetadataManager.requireWritableUserKey(key)
        @Suppress("NAME_SHADOWING") val mode = modeTransformer(mode)
        if (mode is KSafeWriteMode.Encrypted) {
            putEncryptedSuspend(key, value, mode.toProtection()!!, mode.requireUnlockedDevice, serializer)
        } else {
            putPlainSuspend(key, value, serializer)
        }
    }

    fun deleteDirect(key: String) {
        KeySafeMetadataManager.requireWritableUserKey(key)
        writeChannel.trySend(stageDelete(key))
    }

    suspend fun delete(key: String) {
        KeySafeMetadataManager.requireWritableUserKey(key)
        // Route through the coalescer so concurrent deletes + writes share batches.
        val deferred = CompletableDeferred<Unit>()
        writeChannel.send(stageDelete(key, completion = deferred))
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

    /** Single-flight guard for manual rotation, crash recovery, and pending retry. */
    private val rotationInFlight = KSafeAtomicFlag(false)

    private enum class RotateOutcome { ROTATED, SKIPPED, FAILED }

    /**
     * Re-encrypts every encrypted entry under a fresh key generation, then deletes every
     * superseded key nothing references anymore.
     *
     * Resumable by design: each entry's metadata records the generation that decrypts it, so
     * there is no all-or-nothing switch — a crash leaves a mixed-generation store where
     * EVERYTHING stays readable. The generation state also carries a tiny lifecycle marker:
     * the next KSafe instance automatically resumes the SAME target generation, including the
     * final old-master cleanup, even under the default `Never` policy. A completed pass's
     * retryable skipped entries remain readable on their old generation and are marked for a
     * same-generation attempt by the next KSafe instance; definitive failures are left
     * untouched for diagnosis/recovery. Legacy (v1-envelope) entries are upgraded as a side
     * effect.
     *
     * Serialized against user writes through the write consumer: each entry commits under a
     * CAS on its stored ciphertext, so a concurrent write always wins and is never clobbered.
     */
    suspend fun rotateKeys(): KSafeRotationResult {
        ensureCacheReadySuspend()
        check(rotationInFlight.compareAndSet(false, true)) {
            "KSafe: a key rotation is already in progress on this instance"
        }
        try {
            val keygenRaw =
                (storage.snapshot()[KeySafeMetadataManager.KEYGEN_RAW_KEY] as? StoredValue.Text)?.value
            val lifecycle = KeySafeMetadataManager.parseKeyRotationLifecycle(keygenRaw)
            val hasLifecycle = KeySafeMetadataManager.hasKeyRotationLifecycle(keygenRaw)
            val isLegacy30 =
                KeySafeMetadataManager.isLegacy30KeyGenerationState(keygenRaw)
            check(
                KeySafeMetadataManager.hasSupportedKeyRotationRetryState(keygenRaw) &&
                    (
                        keygenRaw == null ||
                            isLegacy30 ||
                            (hasLifecycle && (lifecycle == 0 || lifecycle == 1))
                        )
            ) {
                "KSafe: unsupported key-rotation lifecycle/retry marker; " +
                    "the store was left untouched"
            }
            val resuming = lifecycle == 1
            val targetGeneration = if (resuming) {
                KeySafeMetadataManager.parseKeyGeneration(keygenRaw).also {
                    currentKeyGeneration.raiseToAtLeast(it)
                }
            } else {
                val next = currentKeyGeneration.get() + 1
                // The generation is plaintext routing metadata bounded by
                // parseKeyGeneration's clamp; refusing here keeps the increment from ever
                // exceeding (or wrapping past) what the parsers and sweep loops accept.
                check(next <= KeySafeMetadataManager.MAX_KEY_GENERATION) {
                    "KSafe: key rotation refused — the store is at generation " +
                        "${next - 1}, the maximum this format supports " +
                        "(${KeySafeMetadataManager.MAX_KEY_GENERATION})."
                }

                // Persist bump + recovery marker FIRST, through the consumer. Every write
                // ordered after it uses the new generation, and a process death at any later
                // instruction leaves enough durable state for the next instance to resume.
                val bumped = CompletableDeferred<Unit>()
                writeChannel.send(
                    PendingWrite.SetKeyGeneration(
                        generation = next,
                        timestampMillis = ksafeEpochMillis(),
                        rotationInProgress = true,
                        completion = bumped,
                    )
                )
                bumped.await()
                next
            }
            val retriesAfterThisPass =
                if (resuming) {
                    KeySafeMetadataManager.parseKeyRotationRetryAttempts(keygenRaw)
                        ?.takeUnless { config.keyRotationRetryAttempts == 0 }
                        ?: config.keyRotationRetryAttempts
                } else {
                    config.keyRotationRetryAttempts
                }
            return rotateIntoGeneration(targetGeneration, retriesAfterThisPass)
        } finally {
            rotationInFlight.set(false)
        }
    }

    /**
     * Startup-only recovery. A simultaneous manual pass owns the instance guard and already
     * covers the work, so startup quietly yields instead of surfacing the public API's
     * concurrent-call exception.
     */
    private suspend fun resumeInterruptedRotation(): KSafeRotationResult? {
        if (!rotationInFlight.compareAndSet(false, true)) return null
        try {
            // Re-check after taking the guard: another same-file instance may have completed
            // the pass between startup's first snapshot and this coroutine being scheduled.
            val raw =
                (storage.snapshot()[KeySafeMetadataManager.KEYGEN_RAW_KEY] as? StoredValue.Text)?.value
            if (!KeySafeMetadataManager.parseKeyRotationInProgress(raw)) return null
            val durableTarget = KeySafeMetadataManager.parseKeyGeneration(raw)
            val retriesAfterThisPass =
                KeySafeMetadataManager.parseKeyRotationRetryAttempts(raw)
                    ?.takeUnless { config.keyRotationRetryAttempts == 0 }
                    ?: config.keyRotationRetryAttempts
            currentKeyGeneration.raiseToAtLeast(durableTarget)
            return rotateIntoGeneration(durableTarget, retriesAfterThisPass)
        } finally {
            rotationInFlight.set(false)
        }
    }

    /**
     * Startup-only retry for a normally completed pass that left retryable work. Claims the
     * durable `r:0,rp:N -> r:1,rp:N-1` state, then retries only entries behind the current
     * generation. It never creates another generation and never changes the generation-birth
     * timestamp. Decrementing before the work makes the budget crash-safe.
     *
     * If the device is still locked, completion persists the remaining positive budget; this
     * instance does not loop, and only the next KSafe instance may consume another attempt.
     */
    private suspend fun retryPendingRotationAtStartup(): KSafeRotationResult? {
        if (!rotationInFlight.compareAndSet(false, true)) return null
        try {
            // Re-read after taking the instance guard. A manual pass or sibling instance may
            // already have claimed/completed the store since startup's first snapshot.
            val currentRaw =
                (storage.snapshot()[KeySafeMetadataManager.KEYGEN_RAW_KEY] as? StoredValue.Text)?.value
            if (
                KeySafeMetadataManager.parseKeyRotationLifecycle(currentRaw) != 0
            ) {
                return null
            }
            val remaining =
                KeySafeMetadataManager.parseKeyRotationRetryAttempts(currentRaw)
                    ?.takeIf { it > 0 }
                    ?: return null

            val target = KeySafeMetadataManager.parseKeyGeneration(currentRaw)
            val started = CompletableDeferred<Unit>()
            val claim = PendingWrite.SetKeyGeneration(
                generation = target,
                timestampMillis =
                    KeySafeMetadataManager.parseKeyGenerationTimestamp(currentRaw)
                        ?: ksafeEpochMillis(),
                rotationInProgress = true,
                claimPendingRetry = true,
                completion = started,
            )
            writeChannel.send(claim)
            started.await()
            if (!claim.applied.get()) return null

            currentKeyGeneration.raiseToAtLeast(target)
            return rotateIntoGeneration(target, remaining - 1)
        } finally {
            rotationInFlight.set(false)
        }
    }

    /** Re-encrypts entries into an already-persisted target generation; never bumps it. */
    private suspend fun rotateIntoGeneration(
        newGeneration: Int,
        retryAttemptsRemainingOnSkip: Int = config.keyRotationRetryAttempts,
    ): KSafeRotationResult {
        val clearEpochAtStart = clearEpoch.get()
        // Candidate set from a post-bump snapshot: encrypted entries still on an older
        // generation (or a legacy envelope). Metadata is parsed from the same snapshot
        // the ciphertext is read from, so alias derivation is self-consistent.
        data class Candidate(
            val userKey: String,
            val protection: KSafeProtection,
            val ciphertextB64: String,
            val meta: EncMeta,
        )
        val snapshot = storage.snapshot()
        val metadataEntries = snapshot.map { (rawKey, storedValue) ->
            rawKey to (storedValue as? StoredValue.Text)?.value
        }
        val metaByKey = KeySafeMetadataManager.collectMetadata(metadataEntries, accept = { true })
        val candidates = metaByKey.mapNotNull { (userKey, rawMeta) ->
            val protection = KeySafeMetadataManager.parseProtection(rawMeta) ?: return@mapNotNull null
            val meta = encMetaFromRaw(rawMeta)
            if (meta.keyGeneration >= newGeneration) return@mapNotNull null
            val ciphertext = (snapshot[valueRawKey(userKey)] as? StoredValue.Text)?.value
                ?: (snapshot[legacyEncryptedRawKey(userKey)] as? StoredValue.Text)?.value
                ?: return@mapNotNull null
            Candidate(
                userKey = userKey,
                protection = protection,
                ciphertextB64 = ciphertext,
                meta = meta,
            )
        }

        var rotated = 0
        var skipped = 0
        var failed = 0

        // A chunk at a time, and the gate matches it, so [ROTATION_IN_FLIGHT] is the single
        // bound on how much of the store is decrypted simultaneously — the property
        // JvmRotationConcurrencyBoundTest pins.
        for (chunk in candidates.chunked(ROTATION_IN_FLIGHT)) {
            val gate = Semaphore(ROTATION_IN_FLIGHT)
            val outcomes = coroutineScope {
                chunk.map { c ->
                    async {
                        gate.withPermit {
                            val oldAlias = aliasForRawMeta(c.userKey, c.protection, c.meta)
                            val plainBytes = try {
                                // Future-format entries fail closed: counted failed (this
                                // build can never rotate them), value left untouched.
                                decryptEntry(
                                    c.userKey, c.protection,
                                    KSafeBase64.decode(c.ciphertextB64), c.meta,
                                )
                            } catch (e: Throwable) {
                                if (e is CancellationException) throw e
                                // A locked strict entry OR a temporary key-store outage is
                                // retried by the next rotation (the entry stays readable
                                // under its recorded generation); only a definitive failure
                                // (e.g. the key genuinely gone) is reported as failed.
                                return@withPermit if (isRotationRetryable(e)) {
                                    RotateOutcome.SKIPPED
                                } else {
                                    RotateOutcome.FAILED
                                }
                            }
                            // The old per-entry key is superseded by this rotation; an old
                            // MASTER is shared, so it is swept below only when unreferenced.
                            val perEntryOldKey =
                                ownsPerEntryAlias(c.protection, c.meta.envelopeVersion)
                            val op = PendingWrite.Rotate(
                                userKey = c.userKey,
                                rawCacheKey = legacyEncryptedRawKey(c.userKey),
                                jsonString = plainBytes.decodeToString(),
                                protection = c.protection,
                                requireUnlockedDevice = c.meta.requireUnlockedDevice,
                                keyGeneration = newGeneration,
                                expectedOldCiphertext = c.ciphertextB64,
                                oldAliasToDelete = if (perEntryOldKey) oldAlias else null,
                                expectedClearEpoch = clearEpochAtStart,
                                ownerTokenAtIssue = writeOwners[c.userKey],
                                completion = CompletableDeferred(),
                            )
                            writeChannel.send(op)
                            try {
                                op.completion.await()
                                if (op.applied.get()) {
                                    RotateOutcome.ROTATED
                                } else {
                                    RotateOutcome.SKIPPED
                                }
                            } catch (e: Throwable) {
                                if (e is CancellationException) throw e
                                // A transient re-encrypt failure (device locked mid-pass,
                                // vault outage) is also a retry-later, not a failure.
                                if (isRotationRetryable(e)) {
                                    RotateOutcome.SKIPPED
                                } else {
                                    RotateOutcome.FAILED
                                }
                            }
                        }
                    }
                }.awaitAll()
            }
            for (outcome in outcomes) when (outcome) {
                RotateOutcome.ROTATED -> rotated++
                RotateOutcome.SKIPPED -> skipped++
                RotateOutcome.FAILED -> failed++
            }
        }

        // Sweep superseded MASTER generations nothing references anymore — THROUGH the
        // consumer, so the deletion is serialized with every write (see
        // [PendingWrite.SweepSupersededMasters] for why an unserialized sweep can
        // destroy an acknowledged concurrent write's key).
        val swept = CompletableDeferred<Unit>()
        writeChannel.send(PendingWrite.SweepSupersededMasters(newGeneration, swept))
        swept.await()

        // Mark the lifecycle completed (`r:1` -> `r:0`) LAST. If the process dies before this
        // durable write, the next instance repeats the idempotent remainder at this SAME
        // generation. The consumer generation-CAS prevents an old pass acknowledging a newer
        // pass as completed.
        val completed = CompletableDeferred<Unit>()
        writeChannel.send(
            PendingWrite.CompleteKeyRotation(
                generation = newGeneration,
                retryAttemptsRemaining =
                    retryAttemptsRemainingOnSkip.takeIf { skipped > 0 && it > 0 },
                completion = completed,
            )
        )
        completed.await()

        return KSafeRotationResult(
            rotated = rotated,
            skipped = skipped,
            failed = failed,
            keyGeneration = newGeneration,
        )
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
        // The same alias the read path decrypts under (recorded generation + master-vs-per-entry
        // routing), so custody inspection looks at the key that actually serves this entry.
        val engineAlias = protection?.let { aliasForRead(key, it) }
        @Suppress("DEPRECATION")
        return KSafeKeyInfo(
            protection = protection,
            storage = resolveKeyStorage(key, protection, engineAlias),
            level = resolveKeyLevel(key, protection, engineAlias),
            keyGeneration = if (protection != null) encMetaMap[key]?.keyGeneration ?: 1 else 1,
        )
    }

    suspend fun ensureCacheReadySuspend() {
        if (cacheInitialized.get()) {
            triggerLazyStartupCleanupOnce()
            return
        }
        // Epoch BEFORE snapshot — the argument-order default would read it after.
        val epoch = clearEpoch.get()
        updateCache(storage.snapshot(), epoch)
        triggerLazyStartupCleanupOnce()
    }

    @Volatile
    internal var siblings: SiblingRegistry? = null
        private set

    internal fun attachSiblings(registry: SiblingRegistry) {
        siblings = registry
        registry.register(this)
    }

    /**
     * Cancels both background scopes (write consumer + snapshot collector), releasing the
     * long-running infrastructure this core owns. Idempotent; after cancel the instance no
     * longer processes puts/reads. Mainly matters for test suites and code that re-creates
     * KSafe mid-process: without it each abandoned instance is pinned in heap by its suspended
     * coroutines (GC roots on Dispatchers.Default), growing the live-set unboundedly.
     */
    internal fun cancel() {
        siblings?.unregister(this)
        // Cancel the scopes only — do NOT close writeChannel: closing it makes the consumer's
        // pending receive() throw ClosedReceiveChannelException (not a CancellationException),
        // which bubbles to the uncaught handler and surfaces in the next test. Cancelling the
        // scope already terminates the consumer, and the channel is then GC'd with the core.
        writeScope.cancel()
        collectorScope.cancel()
        // The consumer is now cancelled, so any write still sitting in the channel will never
        // be processed. Drain them and hand each waiting caller a cancellation — otherwise a
        // suspend put/delete/clearAll await()ing its completion on a still-live scope hangs
        // forever. (We still don't CLOSE the channel — see the note above.)
        val teardown = CancellationException("KSafe was cancelled before this write was processed")
        writeChannel.drainRemaining { it.completion?.cancel(teardown) }
        // Platform hook — cancels the DataStore scope and evicts Android's process-static
        // DataStore cache; without it DataStore's coroutines pin the whole graph in heap.
        runCatching { onCancel() }
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

        // Escapes the one pathological plaintext String that collides with the null sentinel: a
        // user value literally equal to NULL_SENTINEL (or already starting with this NUL-delimited
        // marker, which no ordinary string does) would otherwise be stored raw and read back as
        // null. Only the colliding values carry the prefix; every other string is stored verbatim.
        private const val NULL_ESCAPE_PREFIX: String = "\u0000__KSAFE_ESC__\u0000"

        @PublishedApi
        internal fun encodePlainString(value: String): String =
            if (value == NULL_SENTINEL || value.startsWith(NULL_ESCAPE_PREFIX)) NULL_ESCAPE_PREFIX + value else value

        @PublishedApi
        internal fun decodePlainString(stored: String): String =
            if (stored.startsWith(NULL_ESCAPE_PREFIX)) stored.removePrefix(NULL_ESCAPE_PREFIX) else stored

        /**
         * Alias for one key generation. Generation 1 is the un-suffixed base alias — the exact
         * name every pre-rotation release used, so existing keys need no migration; rotated
         * generations append `.gN`. Used directly only for MASTER aliases, whose sentinel
         * segment is barred from user keys; per-entry aliases go through
         * [perEntryAliasWithGeneration], which disambiguates the suffix.
         */
        @PublishedApi
        internal fun aliasWithGeneration(baseAlias: String, generation: Int): String =
            if (generation <= 1) baseAlias
            else "$baseAlias${KSafeAliasGrammar.GENERATION_SEGMENT}$generation"

        /**
         * The routing record a snapshot's raw metadata resolves to — the same shape
         * [encMetaMap] holds, so a snapshot-derived read routes exactly like a cached one.
         */
        /**
         * How many entries [rotateKeys] may hold decrypted at once.
         *
         * Rotation is the one operation that puts entries in the clear without the caller asking
         * for them, so this is a security bound first and a throughput knob second. It is
         * deliberately NOT [maxParallelEncrypts]: that one sizes CPU-bound crypto, while a
         * rotating entry spends its time waiting on a commit, and reusing it there throttled the
         * write consumer to a fraction of the batch it will take.
         *
         * 64 is measured (Galaxy S24 Ultra): below it the commit count dominates, above it the
         * curve flattens — a 500-entry store gains ~10% at 200 while four times as much of it
         * sits decrypted.
         */
        internal const val ROTATION_IN_FLIGHT = 64

        internal fun encMetaFromRaw(rawMeta: String?): EncMeta {
            // Parsed once for all four fields: the cold-start merge builds one of these per
            // encrypted entry, and reading the fields one at a time re-parsed the same record
            // four times over.
            val meta = parseMetaObject(rawMeta)
            return EncMeta(
                envelopeVersion = KeySafeMetadataManager.envelopeVersionOf(meta),
                requireUnlockedDevice = KeySafeMetadataManager.requireUnlockedDeviceOf(meta),
                keyGeneration = KeySafeMetadataManager.keyGenerationOf(meta),
                strictAliasVariant = KeySafeMetadataManager.strictAliasVariantOf(meta),
            )
        }

        /**
         * The alias an entry's RECORDED metadata resolves to: v2+ DEFAULT rides the master
         * alias for the recorded unlock policy, a strict-variant entry uses its strict
         * per-entry alias, and everything else (v1, HARDWARE_ISOLATED) uses the bare per-entry
         * alias. Single producer for every read, sweep and migration — including the ones
         * outside this class, which pass their own [masterAlias] / [keyAlias] / [keyNamespace].
         * A divergent copy decrypts under the wrong key, which surfaces as a false orphan and
         * then as a deleted entry.
         */
        internal fun aliasForRecordedMeta(
            userKey: String,
            protection: KSafeProtection?,
            envelopeVersion: Int,
            requireUnlockedDevice: Boolean,
            keyGeneration: Int,
            strictAliasVariant: Boolean,
            masterAlias: (Boolean) -> String,
            keyAlias: (String) -> String,
            keyNamespace: String?,
        ): String =
            if (envelopeVersion >= KeySafeMetadataManager.ENVELOPE_VERSION_V2 &&
                protection == KSafeProtection.DEFAULT
            ) {
                aliasWithGeneration(masterAlias(requireUnlockedDevice), keyGeneration)
            } else if (strictAliasVariant) {
                strictPerEntryAliasWithGeneration(keyAlias(userKey), keyGeneration, keyNamespace, userKey)
            } else {
                perEntryAliasWithGeneration(keyAlias(userKey), keyGeneration, keyNamespace, userKey)
            }

        /**
         * The associated data an entry is authenticated under, gated on its envelope version:
         * v3 binds identity + routing metadata, pre-v3 entries were encrypted without
         * associated data and must decrypt without it. Every read, write, sweep and migration
         * derives it here — a re-derived gate that misses one site silently drops
         * authentication on that path.
         */
        internal fun aadForEnvelope(
            identity: String,
            userKey: String,
            protection: KSafeProtection?,
            requireUnlockedDevice: Boolean,
            keyGeneration: Int,
            envelopeVersion: Int,
        ): ByteArray? =
            if (envelopeVersion < KeySafeMetadataManager.ENVELOPE_VERSION_V3) null
            else KeySafeMetadataManager.aadFor(
                identity, userKey, protection, requireUnlockedDevice, keyGeneration,
            )

        /**
         * Whether an entry with this recorded routing owns a per-entry engine key instead of
         * riding the shared master: HARDWARE_ISOLATED always, plus any legacy pre-v2 envelope
         * (whose DEFAULT entries also had per-entry keys). Callers must resolve "no recorded
         * protection" to false BEFORE asking — an unknown entry's derived alias can be
         * byte-identical to a sibling store's live key.
         */
        internal fun ownsPerEntryAlias(protection: KSafeProtection, envelopeVersion: Int): Boolean =
            protection == KSafeProtection.HARDWARE_ISOLATED ||
                envelopeVersion < KeySafeMetadataManager.ENVELOPE_VERSION_V2

        /**
         * Per-entry alias for one key generation. Generation 1 stays the bare base alias
         * (published pre-rotation format). Rotated generations append
         * `.gN.__ksafe_gen__.h<fingerprint>`, where the fingerprint hashes the length-prefixed
         * (store fileName, user key) pair: a plain `.gN` suffix made user key `"foo"` at
         * generation 2 collide with user key `"foo.g2"` at generation 1 (same physical vault
         * key — rotating or deleting one destroyed the other's), and made a default store's
         * dotted key collide with a named store's key at every generation. The fingerprint alone
         * still wasn't injective — the user key `"foo.g2.h<fp(ns,foo)>"` reproduced `"foo"`'s
         * rotated alias verbatim as its bare alias — so the suffix also carries a
         * `__ksafe_gen__` sentinel segment barred from user keys ([KeySafeMetadataManager.requireWritableUserKey]),
         * mirroring the strict variant's `__ksafe_strict__`. Generation-1 aliases are the
         * published format and keep their (documented) dotted-key collision.
         */
        @PublishedApi
        internal fun perEntryAliasWithGeneration(
            baseAlias: String,
            generation: Int,
            keyNamespace: String?,
            userKey: String,
        ): String =
            if (generation <= 1) baseAlias
            else "$baseAlias${KSafeAliasGrammar.GENERATION_SEGMENT}$generation" +
                ".${KSafeReservedKeys.ROTATED_VARIANT}" +
                "${KSafeAliasGrammar.FINGERPRINT_SEGMENT}${aliasFingerprint(keyNamespace, userKey)}"

        /**
         * Strict-variant per-entry alias (3.0.0+): the alias a strict `HARDWARE_ISOLATED`
         * entry's key lives under, distinct from the relaxed [perEntryAliasWithGeneration]
         * so an unlock-policy tighten mints its strict key under a FRESH alias instead of
         * destroying the relaxed one first (the delete-first scheme lost the previous value
         * on any failure between the delete and the durable commit). Always fingerprinted —
         * the variant has no published pre-3.0.0 format to preserve — and suffixed with a
         * `__ksafe_strict__` sentinel segment barred from user keys, so no dotted user key
         * can collide with it.
         */
        @PublishedApi
        internal fun strictPerEntryAliasWithGeneration(
            baseAlias: String,
            generation: Int,
            keyNamespace: String?,
            userKey: String,
        ): String {
            val gen = if (generation <= 1) "" else "${KSafeAliasGrammar.GENERATION_SEGMENT}$generation"
            return "$baseAlias$gen.${KSafeReservedKeys.STRICT_VARIANT}" +
                "${KSafeAliasGrammar.FINGERPRINT_SEGMENT}${aliasFingerprint(keyNamespace, userKey)}"
        }

        /**
         * FNV-1a 64-bit over the length-prefixed identity; fixed-width lowercase hex.
         * Internal (not private): the Keychain orphan classification verifies a candidate
         * owner against a parsed strict-variant suffix with it — a `.gN` run before the
         * sentinel is ambiguous (generation suffix vs literal user-key characters), and
         * only the fingerprint can say which owner the key actually belongs to.
         */
        internal fun aliasFingerprint(keyNamespace: String?, userKey: String): String {
            val ns = keyNamespace ?: ""
            val input = "${ns.length}:$ns|${userKey.length}:$userKey"
            // Deliberately hashes UTF-16 code units, unlike [namespaceCollisionDigest]'s UTF-8
            // bytes: both spell live on-disk identities, so neither may adopt the other's domain.
            var hash = FNV1A_64_OFFSET_BASIS
            for (ch in input) {
                hash = hash xor ch.code.toLong()
                hash *= FNV1A_64_PRIME
            }
            return hash.toULong().toString(16).padStart(KSafeAliasGrammar.FINGERPRINT_HEX_LENGTH, '0')
        }
    }

    init {
        startWriteConsumer()
        if (!lazyLoad) startBackgroundCollector()
        prewarmMasterKeys()
    }
}
