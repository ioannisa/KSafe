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
import eu.anifantakis.lib.ksafe.internal.coreparts.convertStoredValue
import eu.anifantakis.lib.ksafe.internal.coreparts.decryptEntry
import eu.anifantakis.lib.ksafe.internal.coreparts.drainRemaining
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
import eu.anifantakis.lib.ksafe.internal.coreparts.stageEncryptedWrite
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

private class TransientDecryptRetry(cause: Throwable) : Exception(cause)

/** Platform-independent engine between the public [KSafe] API and the platform backends. Owns
 *  the hot cache, write coalescer, protection metadata, preload, and orphan cleanup. */
@PublishedApi
internal class KSafeCore(
    @PublishedApi internal val storage: KSafePlatformStorage,
    /** Stable store identity bound into the v3 authenticated envelope: the store's absolute path,
     *  or the normalized fileName on Web. Blocks ciphertext transplanted from another store; not
     *  the appNamespace, which may legitimately change across upgrades. */
    @PublishedApi internal val storeIdentity: String = "",
    /** Non-canonical identity spelling some v3 entries may be bound to; blank or equal to
     *  [storeIdentity] in the common case. Retried on decrypt before falling back to defaults,
     *  then re-bound to [storeIdentity] by the next write or rotation. */
    @PublishedApi internal val fallbackStoreIdentity: String = "",
    /** The store's key-namespace token (normalized fileName; null for the default store), folded
     *  into rotated per-entry alias fingerprints so they cannot be shadowed across stores. */
    @PublishedApi internal val keyNamespace: String? = null,
    /** Serializes batch commits across instances sharing one file: the backends pass one mutex
     *  per store, so two cores cannot interleave each other's snapshot→commit sequences. */
    @PublishedApi internal val commitMutex: Mutex = Mutex(),
    /** Deferred so the platform shell can swap in a test engine after wiring. */
    engineProvider: () -> KSafeEncryption,
    private val config: KSafeConfig,
    @PublishedApi internal val memoryPolicy: KSafeMemoryPolicy,
    @PublishedApi internal val plaintextCacheTtl: Duration,
    /** Storage tier reported by `getKeyInfo`. `engineAlias` is the alias the entry's envelope
     *  decrypts under (null when plain), so shells can report the live key's real custody. */
    private val resolveKeyStorage: (userKey: String, protection: KSafeProtection?, engineAlias: String?) -> KSafeKeyStorage,
    /** Per-key [KSafeProtectionLevel] reported by `getKeyInfo`; same `engineAlias` contract as [resolveKeyStorage]. */
    private val resolveKeyLevel: (userKey: String, protection: KSafeProtection?, engineAlias: String?) -> KSafeProtectionLevel,
    /** Per-platform migration hook run once before orphan cleanup (iOS accessibility tiers). */
    internal val migrateAccessPolicy: suspend (isUserKeyDirty: (String) -> Boolean) -> Unit = {},
    internal val lazyLoad: Boolean = false,
    /** Builds the per-entry Keystore/Keychain alias for a user key. */
    @PublishedApi internal val keyAlias: (userKey: String) -> String,
    /** Master alias, one per unlock policy; holds the AES key shared by v2 DEFAULT entries. */
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

    /** Per-encrypted-key envelope info telling the read path which alias decrypts the entry.
     *  Plain entries are never present. */
    @PublishedApi
    internal data class EncMeta(
        val envelopeVersion: Int,
        val requireUnlockedDevice: Boolean,
        val keyGeneration: Int = 1,
        /** `true` when the entry's key lives under the strict alias variant ([strictPerEntryAlias]). */
        val strictAliasVariant: Boolean = false,
    )

    @PublishedApi
    internal val encMetaMap = KSafeConcurrentMap<EncMeta>()

    /** Generation new writes encrypt under; re-synced from the persisted keygen entry on every
     *  snapshot merge, so a co-existing instance's rotation propagates here. */
    @PublishedApi
    internal val currentKeyGeneration = KSafeAtomicInt(1)

    /** False until [currentKeyGeneration] has been reconciled with a persisted snapshot; until then
     *  the local `1` is a default, so the write consumer reads disk instead of regressing the store. */
    internal val keyGenerationReconciled = KSafeAtomicFlag(false)

    /** Bumped by [performClearAll] and on every sibling core: a cache merge or pending rotation
     *  whose snapshot predates the wipe redoes or skips itself instead of republishing secrets. */
    internal val clearEpoch = KSafeAtomicInt(0)

    @PublishedApi
    internal class CachedPlaintext(val value: String, val expiresAt: ComparableTimeMark)

    @PublishedApi
    internal val plaintextCache = KSafeConcurrentMap<CachedPlaintext>()

    /** Latest write's identity token per user key, claimed before any optimistic mutation: a
     *  failed write may only roll back state it still owns. Not wiped by clearAll. */
    internal val writeOwners = KSafeConcurrentMap<Any>()

    // Test-only interleaving seams; null in production.
    @PublishedApi
    internal var postCommitRepairHook: ((String) -> Unit)? = null

    /** Fired with a batch's keys after applyBatch, under commitMutex: never call a suspend write from it. */
    internal var postApplyBatchHook: ((Set<String>) -> Unit)? = null

    internal var sideCacheWriteBackHook: (() -> Unit)? = null

    internal var cacheMergeStoreHook: ((String) -> Unit)? = null

    internal var cacheMergeMetaStoreHook: ((String) -> Unit)? = null

    internal val cacheHoldsCiphertext: Boolean =
        memoryPolicy == KSafeMemoryPolicy.ENCRYPTED ||
            memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE ||
            memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT

    internal val usesPlaintextSideCache: Boolean =
        memoryPolicy == KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE ||
            memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT

    internal fun plaintextStillValid(cached: CachedPlaintext): Boolean =
        memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT ||
            TimeSource.Monotonic.markNow() < cached.expiresAt

    internal fun plaintextExpiry(): ComparableTimeMark =
        if (memoryPolicy == KSafeMemoryPolicy.LAZY_PLAIN_TEXT) TimeSource.Monotonic.markNow()
        else TimeSource.Monotonic.markNow() + plaintextCacheTtl

    @PublishedApi
    internal val cacheInitialized = KSafeAtomicFlag(false)

    /** Set once an encrypted entry is ever seen, so plaintext-only reads skip the map lookups.
     *  Monotonic — never reset. */
    @PublishedApi
    internal val hasAnyEncryptedKey = KSafeAtomicFlag(false)

    /** Raw cache keys with in-flight writes, in both canonical and legacy encrypted forms, so
     *  the background collector never stomps on an optimistic update. */
    @PublishedApi
    internal val dirtyKeys = KSafeConcurrentSet<String>()

    internal val writeScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    internal val collectorScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    /** Logical write queue — encryption happens inside the consumer, not on UI. */
    internal val writeChannel = Channel<PendingWrite>(Channel.UNLIMITED)

    internal val writeCoalesceWindowMs = 16L   // ~1 frame at 60 fps
    internal val maxBatchSize = 200

    /** Caps concurrent encrypt/decrypt calls: unbounded fan-out floods Binder / Keychain and
     *  over-subscribes the dispatcher. */
    internal val maxParallelEncrypts = 8

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

        /** Identity token claimed in [writeOwners] before the issuing call's optimistic
         *  mutations; a failed write may roll back only while it is still the key's latest writer. */
        abstract val writeToken: Any

        /** Failure notification for fire-and-forget callers, invoked after the optimistic
         *  rollback, outside locks, exceptions swallowed; not on close/cancel drains. */
        open val onWriteFailed: ((Throwable) -> Unit)? get() = null

        data class Plain(
            override val userKey: String,
            override val rawCacheKey: String,
            /** A primitive, the null sentinel, or pre-encoded JSON for complex types. */
            val value: Any,
            override val writeToken: Any,
            /** Generation of the overwritten entry when it owned a per-entry alias, 0 otherwise.
             *  Captured before the optimistic map wipe, or the old platform key is left live. */
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
            /** Captured at enqueue so the committed metadata, the encrypt alias and the caller's
             *  optimistic [EncMeta] all name the same key if a rotation lands mid-write. */
            override val keyGeneration: Int = 1,
            /** Per-entry aliases this entry previously resolved to, captured at enqueue before the
             *  optimistic [EncMeta] overwrite hides them. Reclaimed only after this write commits. */
            val supersededAliases: List<String> = emptyList(),
            override val completion: CompletableDeferred<Unit>? = null,
            override val onWriteFailed: ((Throwable) -> Unit)? = null,
        ) : PendingWrite(), EncryptingWrite

        /** Re-encrypts one entry under the NEW [keyGeneration], committed only while the stored
         *  ciphertext still equals [expectedOldCiphertext], so a racing user write always wins. */
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
            /** [clearEpoch] at the pass's start: a clearAll landing mid-pass resets the store's
             *  generation, so the consumer skips rather than stamp the stale target generation. */
            val expectedClearEpoch: Int,
            /** The key's [writeOwners] token at rotation issue. Plaintext-policy caches cannot use
             *  the ciphertext CAS, so an unchanged token is what proves no user write intervened. */
            val ownerTokenAtIssue: Any? = null,
            val applied: KSafeAtomicFlag = KSafeAtomicFlag(false),
            override val completion: CompletableDeferred<Unit>,
        ) : PendingWrite(), EncryptingWrite {
            override val writeToken: Any = Any() // unregistered — rollback machinery ignores rotations
        }

        /** Persists a new store-level key generation, serialized with all writes.
         *  [timestampMillis] is the generation's birth — the age the MaxAge policy measures. */
        data class SetKeyGeneration(
            val generation: Int,
            val timestampMillis: Long,
            /** True only for the bump that starts a rotation, persisted before any entry is
             *  touched, so a later instance resumes this exact generation after process death. */
            val rotationInProgress: Boolean = false,
            /** Claims a completed generation's retry budget: `r:0,rp:N` becomes `r:1,rp:N-1` only
             *  while that state is durable, so neither a crash nor a sibling instance can repeat it. */
            val claimPendingRetry: Boolean = false,
            val applied: KSafeAtomicFlag = KSafeAtomicFlag(false),
            override val completion: CompletableDeferred<Unit>,
        ) : PendingWrite() {
            override val userKey: String get() = KeySafeMetadataManager.KEYGEN_RAW_KEY
            override val rawCacheKey: String get() = KeySafeMetadataManager.KEYGEN_RAW_KEY
            override val writeToken: Any get() = this // never rolled back per-key
        }

        /** Flips the durable lifecycle marker from in-progress (`r:1`) to completed (`r:0`), only
         *  while the store is still at [generation], so a stale pass cannot acknowledge a newer one. */
        data class CompleteKeyRotation(
            val generation: Int,
            /** Persisted only when the pass left retryable entries and an attempt remains;
             *  null means no pending retry. */
            val retryAttemptsRemaining: Int? = null,
            override val completion: CompletableDeferred<Unit>,
        ) : PendingWrite() {
            override val userKey: String get() = KeySafeMetadataManager.KEYGEN_RAW_KEY
            override val rawCacheKey: String get() = KeySafeMetadataManager.KEYGEN_RAW_KEY
            override val writeToken: Any get() = this // never rolled back per-key
        }

        /** Deletes superseded MASTER generations nothing still references. MUST run on the consumer:
         *  unserialized it can delete a key mid-batch and leave an acknowledged write unreadable. */
        data class SweepSupersededMasters(
            val newGeneration: Int,
            override val completion: CompletableDeferred<Unit>,
        ) : PendingWrite() {
            override val userKey: String get() = "__ksafe_sweep_masters__"

            override val rawCacheKey: String get() = userKey
            override val writeToken: Any get() = this // never rolled back per-key
        }

        data class Delete(
            override val userKey: String,
            override val rawCacheKey: String,
            override val writeToken: Any,
            /** The entry's recorded generation, captured BEFORE the optimistic [encMetaMap]
             *  removal — by commit time the map no longer knows which alias the entry used. */
            val keyGeneration: Int = 1,
            /** Whether the entry provably used a per-entry engine alias, captured like [keyGeneration].
             *  Gates the key sweep: a dotted user key's alias can collide with another store's key. */
            val usedPerEntryAlias: Boolean = false,
            /** Whether the entry's key lived under the strict alias variant, captured like
             *  [keyGeneration]; widens the sweep past the reachability prune. */
            val usedStrictAlias: Boolean = false,
            override val completion: CompletableDeferred<Unit>? = null,
        ) : PendingWrite()

        /** Routes [clearAll] through the write channel so the wipe is FIFO-serialized with
         *  concurrent writes; handled as a batch boundary in [processBatchBody]. */
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

    /** Write alias: DEFAULT rides the master alias for the unlock policy, HARDWARE_ISOLATED the
     *  per-entry alias (strict variant when [requireUnlockedDevice], so a relaxed→strict rewrite
     *  never destroys the old key first). [keyGeneration] must match the write's own metadata. */
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

    /** Whether a new USER write here can land on the strict per-entry alias variant (web strips
     *  `requireUnlockedDevice`). Prunes the delete/clearAll sweeps; routing uses every spelling. */
    internal val strictAliasVariantReachable: Boolean =
        (
            modeTransformer(
                KSafeWriteMode.Encrypted(
                    protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
                    requireUnlockedDevice = true,
                )
            ) as? KSafeWriteMode.Encrypted
            )?.requireUnlockedDevice == true

    @PublishedApi
    internal fun perEntryAlias(userKey: String, generation: Int): String =
        perEntryAliasWithGeneration(keyAlias(userKey), generation, keyNamespace, userKey)

    @PublishedApi
    internal fun strictPerEntryAlias(userKey: String, generation: Int): String =
        strictPerEntryAliasWithGeneration(keyAlias(userKey), generation, keyNamespace, userKey)

    /** AAD for reading [userKey] under its RECORDED envelope; see [aadForEnvelope]. */
    @PublishedApi
    internal fun aadForRead(userKey: String, protection: KSafeProtection?): ByteArray? {
        val em = encMetaMap[userKey] ?: return null
        return aadForEnvelope(
            storeIdentity, userKey, protection,
            em.requireUnlockedDevice, em.keyGeneration, em.envelopeVersion,
        )
    }

    internal val hasFallbackIdentity: Boolean =
        fallbackStoreIdentity.isNotEmpty() && fallbackStoreIdentity != storeIdentity

    /** Read alias from the entry's recorded envelope: its OWN generation picks the alias, never
     *  the store's current one, so a not-yet-rotated entry keeps decrypting. */
    @PublishedApi
    internal fun aliasForRead(userKey: String, protection: KSafeProtection?): String =
        aliasForRawMeta(userKey, protection, encMetaMap[userKey])

    internal val startupCleanupDone = KSafeAtomicFlag(false)
    internal val lazyStartupCleanupLaunched = KSafeAtomicFlag(false)

    /** Runs rotation maintenance once per startup on the background scope, never blocking reads. An
     *  interrupted pass resumes at its persisted generation whatever the configured policy. */
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
                    // A missing lifecycle field is proof of the old completed format, never of a
                    // crash: adopt it as r:0 and do nothing else this launch.
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
                        // Unknown age: start the clock now rather than rotate on first sight.
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

    /** Merges an on-disk snapshot into the memory cache, skipping dirty (in-flight) keys.
     *  [epochAtSnapshot] must be read from [clearEpoch] BEFORE the snapshot is taken, or a merge
     *  predating a concurrent [performClearAll] republishes wiped secrets after it returned. */
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
            // Bounded: each retry needs ANOTHER clearAll to land mid-merge, and the collector
            // plus the clear's own map wipe bound the residue if the cap trips.
            if (clearEpoch.get() == epoch || ++attempts >= 3) return
            epoch = clearEpoch.get()
            snap = storage.snapshot()
        }
    }

    @PublishedApi
    internal fun detectProtection(key: String): KSafeProtection? {
        if (!hasAnyEncryptedKey.get()) return null

        // Metadata is authoritative, including the explicit "NONE"; the heuristic is legacy-only.
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
            // Non-suspend read path: no retry seam here, so a transient decrypt failure returns
            // the default rather than crash property access or composition. get() still rethrows.
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

    /** A transient decrypt failure never reaches collectors as a value or a throw — long-lived
     *  observers would crash and stop observing; the flow resubscribes on a backoff instead. */
    @PublishedApi
    internal fun getFlowRaw(
        key: String,
        defaultValue: Any?,
        serializer: KSerializer<*>,
    ): Flow<Any?> {
        return storage.snapshotFlow()
            // Resubscribe on a transient upstream read error instead of terminating the user's
            // flow exceptionally. Before .map, so only the storage read retries here.
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
                    // Fail closed: a canonical value slot with absent or tampered metadata holds
                    // ciphertext, so decrypt it rather than serve base64 as plaintext.
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
                            // Derive the alias from the meta just parsed, not from encMetaMap,
                            // which may lag behind a freshly arrived snapshot.
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
            // Decrypt off the collector's dispatcher: .map does keystore IPC and stateIn usually
            // collects on Main, so without flowOn every emission risks an ANR.
            .flowOn(decryptFlowContext)
            // AFTER flowOn so a retry re-collects the WHOLE upstream: storage re-delivers its
            // current snapshot, the only way to see the value again without a write.
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

    /** [putDirectRaw] plus a fire-and-forget failure notification; a separate overload rather
     *  than a default parameter so the original entry point's inline ABI stays untouched. */
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
            // Serialize FIRST: a throwing serializer must leave no trace — once the ownership
            // token, dirty flag or routing metadata are touched, nothing repairs them.
            val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)
            writeChannel.trySend(
                stageEncryptedWrite(
                    key, jsonString, protection, requireUnlockedDevice, onWriteFailed = onWriteFailed,
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
        val deferred = CompletableDeferred<Unit>()
        writeChannel.send(stageDelete(key, completion = deferred))
        deferred.await()
    }

    suspend fun clearAll() {
        // Populate the cache first: performClearAll runs on the consumer and reads protectionMap
        // to learn which per-entry engine keys to delete.
        ensureCacheReadySuspend()
        // Route the wipe THROUGH the write channel so it is serialized with concurrent writes: a
        // put enqueued before this call can no longer be applied after the wipe and resurrect data.
        val deferred = CompletableDeferred<Unit>()
        writeChannel.send(PendingWrite.ClearAll(completion = deferred))
        deferred.await()
    }

    private val rotationInFlight = KSafeAtomicFlag(false)

    private enum class RotateOutcome { ROTATED, SKIPPED, FAILED }

    /** Re-encrypts every encrypted entry under a fresh key generation, then deletes the
     *  superseded keys. Resumable: each entry records the generation that decrypts it, so an
     *  interrupted pass stays readable and the next instance finishes it; a live write wins. */
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
                // Refuse before the increment can exceed what the parsers and sweep loops accept.
                check(next <= KeySafeMetadataManager.MAX_KEY_GENERATION) {
                    "KSafe: key rotation refused — the store is at generation " +
                        "${next - 1}, the maximum this format supports " +
                        "(${KeySafeMetadataManager.MAX_KEY_GENERATION})."
                }

                // Persist bump + recovery marker FIRST, through the consumer: every later write
                // uses the new generation, and a crash leaves enough durable state to resume.
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
            // The persisted budget wins over the configured one, except that a configured 0
            // disables retries outright.
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

    /** Startup-only recovery; yields quietly when a manual pass already owns the guard. */
    private suspend fun resumeInterruptedRotation(): KSafeRotationResult? {
        if (!rotationInFlight.compareAndSet(false, true)) return null
        try {
            // Re-check under the guard: a sibling may have completed the pass since startup.
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

    /** Startup-only retry for a completed pass that left retryable work: claims the durable
     *  `r:0,rp:N -> r:1,rp:N-1` budget BEFORE the work, so a crash cannot refill it. */
    private suspend fun retryPendingRotationAtStartup(): KSafeRotationResult? {
        if (!rotationInFlight.compareAndSet(false, true)) return null
        try {
            // Re-read under the guard: a manual pass or sibling may already have claimed the store.
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
        // Metadata and ciphertext come from one post-bump snapshot, so alias derivation agrees.
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

        // A chunk at a time, with a matching gate, so ROTATION_IN_FLIGHT is the single bound on
        // how much of the store is decrypted simultaneously.
        for (chunk in candidates.chunked(ROTATION_IN_FLIGHT)) {
            val gate = Semaphore(ROTATION_IN_FLIGHT)
            val outcomes = coroutineScope {
                chunk.map { c ->
                    async {
                        gate.withPermit {
                            val oldAlias = aliasForRawMeta(c.userKey, c.protection, c.meta)
                            val plainBytes = try {
                                // Future-format entries fail closed: counted failed, value untouched.
                                decryptEntry(
                                    c.userKey, c.protection,
                                    KSafeBase64.decode(c.ciphertextB64), c.meta,
                                )
                            } catch (e: Throwable) {
                                if (e is CancellationException) throw e
                                // A locked entry or a transient vault outage is retried by the
                                // next pass; only a definitive failure counts as failed.
                                return@withPermit if (isRotationRetryable(e)) {
                                    RotateOutcome.SKIPPED
                                } else {
                                    RotateOutcome.FAILED
                                }
                            }
                            // A superseded per-entry key dies here; a shared master is swept below.
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
                                // A transient re-encrypt failure is a retry-later, not a failure.
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

        // Sweep superseded MASTER generations THROUGH the consumer, serialized with every write.
        val swept = CompletableDeferred<Unit>()
        writeChannel.send(PendingWrite.SweepSupersededMasters(newGeneration, swept))
        swept.await()

        // Mark the lifecycle completed LAST: a crash before this durable write makes the next
        // instance repeat the idempotent remainder at this SAME generation.
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
        // An entry can exist on disk yet be absent from memoryCache (undecryptable entries are
        // dropped), so consult protectionMap too or a new secret overwrites a live one.
        val hasMetadata = protectionMap.containsKey(key)
        if (!hasEncrypted && !hasPlain && !hasMetadata) return null
        val protection = KeySafeMetadataManager.parseProtection(protectionMap[key])
            ?: if (hasEncrypted) KSafeProtection.DEFAULT else null
        // The same alias the read path decrypts under, so custody inspection sees the live key.
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

    /** Cancels both background scopes; idempotent, and afterwards the instance no longer processes
     *  puts or reads. Without it an abandoned instance stays pinned in heap by its coroutines. */
    internal fun cancel() {
        siblings?.unregister(this)
        // Cancel the scopes only — do NOT close writeChannel: a close makes the consumer's
        // pending receive() throw ClosedReceiveChannelException at the uncaught handler.
        writeScope.cancel()
        collectorScope.cancel()
        // The consumer is gone, so queued writes will never be processed: hand each waiting
        // caller a cancellation, or a suspend put/delete/clearAll awaits forever.
        val teardown = CancellationException("KSafe was cancelled before this write was processed")
        writeChannel.drainRemaining { it.completion?.cancel(teardown) }
        // Platform hook — without it DataStore's coroutines pin the whole graph in heap.
        runCatching { onCancel() }
    }

    companion object {
        /** Marker stored on disk for a persisted `null`, so "absent" and "null" stay distinct. */
        @PublishedApi
        internal const val NULL_SENTINEL: String = "__KSAFE_NULL_VALUE__"

        @PublishedApi
        internal fun isNullSentinel(value: Any?): Boolean = value == NULL_SENTINEL

        // Prefixes a plaintext String equal to the sentinel (or already carrying this prefix), so
        // decode never mistakes it for a stored null.
        private const val NULL_ESCAPE_PREFIX: String = "\u0000__KSAFE_ESC__\u0000"

        @PublishedApi
        internal fun encodePlainString(value: String): String =
            if (value == NULL_SENTINEL || value.startsWith(NULL_ESCAPE_PREFIX)) NULL_ESCAPE_PREFIX + value else value

        @PublishedApi
        internal fun decodePlainString(stored: String): String =
            if (stored.startsWith(NULL_ESCAPE_PREFIX)) stored.removePrefix(NULL_ESCAPE_PREFIX) else stored

        /** Alias for one key generation; generation 1 is the un-suffixed base every pre-rotation
         *  release used, so existing keys need no migration. MASTER aliases only — per-entry ones
         *  go through [perEntryAliasWithGeneration]. */
        @PublishedApi
        internal fun aliasWithGeneration(baseAlias: String, generation: Int): String =
            if (generation <= 1) baseAlias
            else "$baseAlias${KSafeAliasGrammar.GENERATION_SEGMENT}$generation"

        /** How many entries [rotateKeys] may hold decrypted at once — a security bound first, a
         *  throughput knob second. Not [maxParallelEncrypts], which sizes CPU-bound crypto. */
        internal const val ROTATION_IN_FLIGHT = 64

        internal fun encMetaFromRaw(rawMeta: String?): EncMeta {
            val meta = parseMetaObject(rawMeta)
            return EncMeta(
                envelopeVersion = KeySafeMetadataManager.envelopeVersionOf(meta),
                requireUnlockedDevice = KeySafeMetadataManager.requireUnlockedDeviceOf(meta),
                keyGeneration = KeySafeMetadataManager.keyGenerationOf(meta),
                strictAliasVariant = KeySafeMetadataManager.strictAliasVariantOf(meta),
            )
        }

        /** The alias an entry's RECORDED metadata resolves to. Single producer for every read, sweep
         *  and migration: a divergent copy decrypts under the wrong key and the entry looks orphaned. */
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

        /** The associated data an entry is authenticated under, gated on envelope version: v3 binds
         *  identity + routing, pre-v3 decrypts without any. A re-derived copy drops authentication. */
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

        /** Whether an entry with this routing owns a per-entry engine key instead of riding the shared
         *  master. Callers treat a missing recorded protection as false: a dotted key's alias can
         *  equal another store's live key. */
        internal fun ownsPerEntryAlias(protection: KSafeProtection, envelopeVersion: Int): Boolean =
            protection == KSafeProtection.HARDWARE_ISOLATED ||
                envelopeVersion < KeySafeMetadataManager.ENVELOPE_VERSION_V2

        /** Per-entry alias for one key generation. Generation 1 stays the bare base alias (the
         *  published format, with its documented dotted-key collision); rotated ones add `.gN`, a
         *  `__ksafe_gen__` sentinel barred from user keys, and a fingerprint that makes it injective. */
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

        /** The alias a strict `HARDWARE_ISOLATED` entry's key lives under, distinct from the
         *  relaxed [perEntryAliasWithGeneration] so an unlock-policy tighten mints its strict key
         *  under a FRESH alias instead of destroying the relaxed one first. */
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

        /** FNV-1a 64-bit over the length-prefixed identity, fixed-width lowercase hex. Internal,
         *  not private: the Keychain orphan classification verifies a candidate owner with it. */
        internal fun aliasFingerprint(keyNamespace: String?, userKey: String): String {
            val ns = keyNamespace ?: ""
            val input = "${ns.length}:$ns|${userKey.length}:$userKey"
            // Hashes UTF-16 code units, unlike [namespaceCollisionDigest]'s UTF-8 bytes: both
            // spell live on-disk identities, so neither may adopt the other's.
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
