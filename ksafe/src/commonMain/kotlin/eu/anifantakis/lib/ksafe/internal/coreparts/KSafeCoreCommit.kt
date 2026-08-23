package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.KSafeBase64
import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.NULL_SENTINEL
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.aliasWithGeneration
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.encMetaFromRaw
import eu.anifantakis.lib.ksafe.internal.KSafeCore.EncMeta
import eu.anifantakis.lib.ksafe.internal.KSafeCore.EncryptingWrite
import eu.anifantakis.lib.ksafe.internal.KSafeCore.PendingWrite
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.ksafeLogError
import eu.anifantakis.lib.ksafe.internal.primitiveToStoredValue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

/**
 * The storage ops that make one entry's committed state: its canonical value and metadata
 * records, plus deletion of the three v1.6/1.7 layouts the entry may still occupy. Emitted as one
 * unit — an entry left holding a legacy record alongside its canonical one reads back through the
 * legacy path and ignores the metadata that routes its decrypt.
 */
private fun KSafeCore.entryRecordOps(
    key: String,
    value: StoredValue,
    metaJson: String,
): List<StorageOp> = listOf(
    StorageOp.Put(valueRawKey(key), value),
    StorageOp.Put(metaRawKey(key), StoredValue.Text(metaJson)),
    StorageOp.Delete(key),
    StorageOp.Delete(legacyEncryptedRawKey(key)),
    StorageOp.Delete(legacyProtectionRawKey(key)),
)

/** [entryRecordOps] for an already-encrypted payload; shared by the user-write and rotation arms. */
private fun KSafeCore.encryptedEntryRecordOps(op: EncryptingWrite, base64: String): List<StorageOp> =
    entryRecordOps(
        op.userKey,
        StoredValue.Text(base64),
        buildMetaJson(op.protection, op.requireUnlockedDevice, op.keyGeneration),
    )

internal suspend fun KSafeCore.processWrites(batchIn: List<PendingWrite>) {
    // The PERSISTED generation is the authority; the local atomic is only its cache.
    // One suspend disk read, exactly when it's needed: the first batch on an instance
    // whose cache never merged a snapshot (a cold/lazy reopen's immediate write must not
    // regress a rotated store to generation 1), and any batch carrying a SetKeyGeneration
    // or CompleteKeyRotation (both must compare against the current durable lifecycle state).
    // Serialized under commitMutex, so the value can't be concurrently rewritten.
    //
    // Under lazyLoad there is no snapshot collector, so that first read is otherwise the ONLY
    // time this instance learns the store's generation: a co-existing instance's rotation would
    // go unseen and every later write would mint keys and metadata under the superseded one.
    // Re-read per batch there, but only for a batch that encrypts — nothing else consults the
    // generation, and the read is a full store scan on the web backend.
    var persistedKeygenRaw: String? = null
    val refreshForLazyEncrypt = lazyLoad && batchIn.any { it is EncryptingWrite }
    if (!keyGenerationReconciled.get() ||
        refreshForLazyEncrypt ||
        batchIn.any {
            it is PendingWrite.SetKeyGeneration || it is PendingWrite.CompleteKeyRotation
        }
    ) {
        // This read happens BEFORE the commit's own try/catch, so its failure (a DataStore
        // read IOException) would otherwise fail every awaiter while the batch's optimistic
        // cache stayed applied — reads would then serve never-persisted values for the
        // process lifetime, with the dirty flags blocking the collector's repair.
        persistedKeygenRaw = try {
            (storage.snapshot()[KeySafeMetadataManager.KEYGEN_RAW_KEY] as? StoredValue.Text)?.value
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
            reclaimBatchOwnershipToSurvivors(batchIn, batchIn)
            rollbackOptimisticState(batchIn)
            throw e
        }
        currentKeyGeneration.raiseToAtLeast(KeySafeMetadataManager.parseKeyGeneration(persistedKeygenRaw))
        keyGenerationReconciled.set(true)
    }

    // Clamp user writes onto the store generation, in BOTH directions. Above: a write
    // enqueued just before a clearAll captured the pre-reset generation; ordered after the
    // wipe it legitimately survives, but committing it above the store generation would
    // exile it from every future rotation (candidates require generation < new) and mint a
    // master a later clearAll's 1..current sweep never deletes. Below: a cold/lazy
    // instance's write captured the constructor default before the reconcile above raised
    // it — committing it low would drop a rotated store's entry back to a v2 envelope (no
    // AAD). Same-batch writes with a SetKeyGeneration keep their captured generation (the
    // bump applies to the NEXT batch, matching the rotation's post-bump candidate
    // snapshot); Rotate ops carry the deliberate NEW generation and are fenced separately.
    val storeGeneration = currentKeyGeneration.get()
    val clampRepairs = mutableMapOf<String, Pair<EncMeta, EncMeta>>()
    val batch = batchIn.map { op ->
        if (op is PendingWrite.Encrypted && op.keyGeneration != storeGeneration) {
            val stale = encMetaForWrite(op.protection, op.requireUnlockedDevice, op.keyGeneration)
            val clamped = encMetaForWrite(op.protection, op.requireUnlockedDevice, storeGeneration)
            clampRepairs[op.userKey] = stale to clamped
            op.copy(keyGeneration = storeGeneration)
        } else op
    }

    val aliasesToDelete = mutableListOf<String>()
    val encryptedCiphertext = mutableMapOf<String, ByteArray>()

    // Coalesce to the LAST write per userKey: every op fully determines a key's final
    // state, so applying only the last op per key is equivalent to applying the window in
    // order. It also stops a same-batch delete+put from both running — the delete's
    // engine.deleteKey would otherwise orphan the just-written entry's per-entry key.
    //
    // EXCEPTION: a Rotate must never displace a USER op for the same key sharing this
    // batch. It would erase the user write before any storage op is emitted, its awaiter
    // would still be acknowledged, and the Rotate's CAS — which compares against the disk
    // state from BEFORE the erased write — would pass and commit a re-encryption of the
    // stale value: an acknowledged write lost (or a delete resurrected) on the next cold
    // start. The user op wins; the rotation is skipped (applied stays false → reported
    // as skipped, picked up by the next pass). The reverse order needs no guard — a user
    // op enqueued after the Rotate legitimately supersedes it.
    //
    // A second exception is the reserved generation record. Startup's one-time 3.0 adoption
    // (`gN/r:0`) can race an explicit rotation bump (`gN+1/r:1`) into the same coalescing
    // window. Ordinary last-write-wins would let a later, lower adoption displace the bump
    // while BOTH awaiters are acknowledged, after which the pass would write gN+1 entries
    // under a store still claiming gN. For two SetKeyGeneration ops, the higher generation
    // therefore wins regardless of queue order; at the same generation, in-progress wins
    // over a passive timestamp/adoption write.
    val finalByKey = LinkedHashMap<String, PendingWrite>()
    for (op in batch) {
        if (op is PendingWrite.Rotate && finalByKey.containsKey(op.userKey)) continue
        val existing = finalByKey[op.userKey]
        if (op is PendingWrite.SetKeyGeneration &&
            existing is PendingWrite.SetKeyGeneration
        ) {
            val winner = when {
                op.generation > existing.generation -> op
                op.generation < existing.generation -> existing
                op.rotationInProgress && !existing.rotationInProgress -> op
                !op.rotationInProgress && existing.rotationInProgress -> existing
                else -> op
            }
            finalByKey[op.userKey] = winner
            continue
        }
        val displaced = finalByKey.put(op.userKey, op)
        // A displaced write's superseded-alias captures must survive the coalescing: it
        // observed the entry's pre-transition alias, while the winner enqueued after it
        // saw only the displaced write's optimistic post-transition metadata. Unioned —
        // a transition chain contributes every hop's old alias. The commit phase
        // re-compares against the winner's actual alias and the live-alias guard
        // filters anything the winner still resolves to.
        if (op is PendingWrite.Encrypted &&
            displaced is PendingWrite.Encrypted && displaced.supersededAliases.isNotEmpty()
        ) {
            val merged = (displaced.supersededAliases + op.supersededAliases).distinct()
            if (merged != op.supersededAliases) {
                finalByKey[op.userKey] = op.copy(supersededAliases = merged)
            }
        }
    }

    val toEncrypt = finalByKey.values.filterIsInstance<EncryptingWrite>()

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
                        val alias = aliasForWrite(op.userKey, op.protection, op.requireUnlockedDevice, op.keyGeneration)
                        // v3 (generation >= 2) envelopes authenticate the entry's identity
                        // + security metadata; generation-1 writes stay v2 (no AAD) so an
                        // un-rotated store remains byte-identical to pre-3.0.0 releases.
                        val aad = aadForRawMeta(
                            op.userKey, op.protection, op.requireUnlockedDevice, op.keyGeneration,
                            KeySafeMetadataManager.envelopeVersionForWrite(op.keyGeneration),
                        )
                        op.userKey to try {
                            Result.success(
                                engine.encryptSuspend(
                                    identifier = alias,
                                    data = op.jsonString.encodeToByteArray(),
                                    hardwareIsolated = op.protection == KSafeProtection.HARDWARE_ISOLATED,
                                    requireUnlockedDevice = op.requireUnlockedDevice,
                                    aad = aad,
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

    // Rotations CAS against the entry's on-disk ciphertext at commit time; read the disk
    // once per batch, and only when the batch actually carries rotations.
    val rotateDiskSnapshot: Map<String, StoredValue>? =
        if (finalByKey.values.any { it is PendingWrite.Rotate }) storage.snapshot() else null
    // The snapshot is already paid for — fold its persisted generation into the local
    // atomic (monotonic) so the Rotate fence below sees a sibling's newer generation.
    (rotateDiskSnapshot?.get(KeySafeMetadataManager.KEYGEN_RAW_KEY) as? StoredValue.Text)?.value?.let { raw ->
        currentKeyGeneration.raiseToAtLeast(KeySafeMetadataManager.parseKeyGeneration(raw))
    }
    val appliedRotations = mutableSetOf<String>()
    val appliedGenerationWrites = mutableSetOf<PendingWrite.SetKeyGeneration>()

    val ops = mutableListOf<StorageOp>()
    for (op in finalByKey.values) {
        when (op) {
            is PendingWrite.Plain -> {
                val key = op.userKey
                val storedValue = if (op.value == NULL_SENTINEL) {
                    StoredValue.Text(NULL_SENTINEL)
                } else {
                    primitiveToStoredValue(op.value)
                }
                ops += entryRecordOps(key, storedValue, buildMetaJson(null))
                // The plain value replaces per-entry-alias ciphertext in this same batch:
                // reclaim the superseded platform key (mirroring the Delete sweep), or it
                // stays live for historical ciphertext copies while the store's inventory
                // no longer knows it exists — invisible to every later clearAll.
                if (op.supersededPerEntryGeneration > 0) {
                    aliasesToDelete += perEntryAliasesThrough(
                        key, op.supersededPerEntryGeneration, op.supersededStrictAlias,
                    )
                }
            }
            is PendingWrite.Encrypted -> {
                // Encrypt failed for this key — exclude it from the commit;
                // its awaiter(s) are failed and its cache rolled back below.
                if (op.userKey in encryptFailures) continue
                val key = op.userKey
                val ciphertext = encryptedCiphertext[key]!!
                ops += encryptedEntryRecordOps(op, KSafeBase64.encode(ciphertext))
                // The write moved the entry off its previous per-entry alias(es) (unlock-
                // policy transition / legacy-strict migration): reclaim the old keys only
                // AFTER the commit, under the live-alias guard. Re-compared against the
                // alias the write actually used — the clamp may have landed it back there.
                if (op.supersededAliases.isNotEmpty()) {
                    val usedAlias = aliasForWrite(key, op.protection, op.requireUnlockedDevice, op.keyGeneration)
                    op.supersededAliases.filterTo(aliasesToDelete) { it != usedAlias }
                }
            }
            is PendingWrite.Rotate -> {
                // Encrypt failed — the awaiter was failed below; nothing to commit.
                if (op.userKey in encryptFailures) continue
                val key = op.userKey
                val diskCiphertext =
                    (rotateDiskSnapshot?.get(valueRawKey(key)) as? StoredValue.Text)?.value
                        ?: (rotateDiskSnapshot?.get(legacyEncryptedRawKey(key)) as? StoredValue.Text)?.value
                // Fence: a clearAll landed after the pass captured its target (epoch moved,
                // or the store generation reset below the target), or the store generation
                // moved past the target (a sibling's further rotation). Committing would
                // stamp the stale target generation onto an entry of a store that is no
                // longer at it — exiled from later rotation passes and re-colliding with
                // the alias namespace when the store re-reaches that generation.
                val fenced = op.expectedClearEpoch != clearEpoch.get() ||
                    currentKeyGeneration.get() != op.keyGeneration
                // CAS: commit only while the entry on disk is EXACTLY what this rotation
                // decrypted — a write committed since then supersedes the rotation. A write
                // still queued BEHIND this batch needs no check here: the consumer applies
                // it later and it simply overwrites the rotated value (the user write wins).
                if (fenced || diskCiphertext != op.expectedOldCiphertext) {
                    // The entry was superseded (or the pass fenced). Reclaim the rotation's
                    // old per-entry alias ONLY when the entry on disk no longer resolves to
                    // it: the superseding write's key generation is captured when it is
                    // issued, so one issued during the generation-bump window re-encrypts
                    // under that SAME old alias — which is then live and must not be deleted
                    // (HARDWARE_ISOLATED has no software fallback; deleting it would lose
                    // the value). The orphan sweep reclaims only ciphertext, never engine
                    // keys, so this is the one place to reclaim a provably-unreferenced one.
                    // (DEFAULT rides the master alias → oldAliasToDelete is null and nothing
                    // is scheduled.)
                    val curMeta = (rotateDiskSnapshot?.get(metaRawKey(key)) as? StoredValue.Text)?.value
                    val curAliasInUse = KeySafeMetadataManager.parseProtection(curMeta)?.let { prot ->
                        // The alias the entry's RECORDED metadata resolves to — not
                        // aliasForWrite: a legacy strict entry still reads from the
                        // bare alias even though a new write would use the variant.
                        aliasForRawMeta(key, prot, encMetaFromRaw(curMeta))
                    }
                    op.oldAliasToDelete?.let { oldAlias ->
                        if (curAliasInUse != oldAlias) aliasesToDelete += oldAlias
                    }
                    // The encrypt phase above already minted this entry's TARGET-generation
                    // key; skipping the commit would strand it in the vault holding no
                    // ciphertext forever (nothing else ever names it). Per-entry aliases
                    // only — a master is shared and swept separately when unreferenced —
                    // and both the disk-routing check here and the post-commit live-alias
                    // guard keep any alias a current entry resolves to.
                    if (op.protection == KSafeProtection.HARDWARE_ISOLATED) {
                        val targetAlias =
                            aliasForWrite(key, op.protection, op.requireUnlockedDevice, op.keyGeneration)
                        if (curAliasInUse != targetAlias) aliasesToDelete += targetAlias
                    }
                    continue
                }
                ops += encryptedEntryRecordOps(op, KSafeBase64.encode(encryptedCiphertext[key]!!))
                op.oldAliasToDelete?.let { aliasesToDelete += it }
                appliedRotations += key
            }
            is PendingWrite.SetKeyGeneration -> {
                // The persisted record is the authority: never write a generation below
                // what a sibling already persisted (a stale instance's rotation must not
                // roll the store's generation back — its own entries would then sit ABOVE
                // the store), and keep an existing birth timestamp when the generation
                // doesn't move (a same-target re-stamp must not reset the MaxAge clock).
                // A legitimate clearAll reset is distinguishable because the wipe removes
                // the record entirely — persistedKeygenRaw is then null and the write
                // proceeds. persistedKeygenRaw was read under this batch's commitMutex.
                val persistedGen = KeySafeMetadataManager.parseKeyGeneration(persistedKeygenRaw)
                val persistedTs = KeySafeMetadataManager.parseKeyGenerationTimestamp(persistedKeygenRaw)
                val persistedLifecycle =
                    KeySafeMetadataManager.parseKeyRotationLifecycle(persistedKeygenRaw)
                val persistedHasLifecycle =
                    KeySafeMetadataManager.hasKeyRotationLifecycle(persistedKeygenRaw)
                val persistedRetryAttempts =
                    KeySafeMetadataManager.parseKeyRotationRetryAttempts(persistedKeygenRaw)
                val claimsPendingRetry =
                    op.claimPendingRetry &&
                        op.generation == persistedGen &&
                        persistedHasLifecycle &&
                        persistedLifecycle == 0 &&
                        persistedRetryAttempts != null &&
                        persistedRetryAttempts > 0
                val writesGenerationState =
                    persistedKeygenRaw == null ||
                        op.generation > persistedGen ||
                        claimsPendingRetry ||
                        (
                            op.generation == persistedGen &&
                                (!persistedHasLifecycle ||
                                    persistedLifecycle == 0 ||
                                    persistedLifecycle == 1) &&
                                (
                                    persistedTs == null ||
                                        !persistedHasLifecycle
                                    )
                            )
                if (writesGenerationState) {
                    ops += StorageOp.Put(
                        KeySafeMetadataManager.KEYGEN_RAW_KEY,
                        StoredValue.Text(
                            KeySafeMetadataManager.buildKeyGenerationState(
                                generation = op.generation,
                                timestampMillis =
                                    if (claimsPendingRetry) {
                                        persistedTs ?: op.timestampMillis
                                    } else {
                                        op.timestampMillis
                                    },
                                rotationInProgress =
                                    claimsPendingRetry ||
                                        op.rotationInProgress ||
                                        (
                                            op.generation == persistedGen &&
                                                KeySafeMetadataManager.parseKeyRotationInProgress(
                                                    persistedKeygenRaw
                                                )
                                            ),
                                retryAttemptsRemaining =
                                    if (
                                        persistedKeygenRaw == null ||
                                        op.generation > persistedGen
                                    ) {
                                        null
                                    } else if (claimsPendingRetry) {
                                        persistedRetryAttempts - 1
                                    } else {
                                        persistedRetryAttempts
                                    },
                            )
                        ),
                    )
                    appliedGenerationWrites += op
                }
            }
            is PendingWrite.CompleteKeyRotation -> {
                // Completion is generation-CAS'd. A stale pass (or a pass fenced by clearAll)
                // must not acknowledge a newer generation as completed. Rewriting only from
                // the explicit in-progress state also keeps this idempotent across retries.
                val persistedGen = KeySafeMetadataManager.parseKeyGeneration(persistedKeygenRaw)
                if (persistedKeygenRaw != null &&
                    persistedGen == op.generation &&
                    KeySafeMetadataManager.parseKeyRotationInProgress(persistedKeygenRaw)
                ) {
                    ops += StorageOp.Put(
                        KeySafeMetadataManager.KEYGEN_RAW_KEY,
                        StoredValue.Text(
                            KeySafeMetadataManager.buildKeyGenerationState(
                                generation = persistedGen,
                                timestampMillis =
                                    KeySafeMetadataManager.parseKeyGenerationTimestamp(
                                        persistedKeygenRaw
                                    ),
                                retryAttemptsRemaining = op.retryAttemptsRemaining,
                            )
                        ),
                    )
                }
            }
            // No storage ops — the deletion runs post-commit (below), against a snapshot
            // taken after this batch's own writes are durable.
            is PendingWrite.SweepSupersededMasters -> Unit
            is PendingWrite.Delete -> {
                val key = op.userKey
                ops += StorageOp.Delete(valueRawKey(key))
                ops += StorageOp.Delete(key)
                ops += StorageOp.Delete(metaRawKey(key))
                ops += StorageOp.Delete(legacyEncryptedRawKey(key))
                ops += StorageOp.Delete(legacyProtectionRawKey(key))
                // Engine-key sweep only when the entry provably used a per-entry alias:
                // for plain, master-riding, or absent entries the derived alias may be
                // another store's live key (dotted-user-key collision), not a no-op.
                if (op.usedPerEntryAlias) {
                    aliasesToDelete += perEntryAliasesThrough(key, op.keyGeneration, op.usedStrictAlias)
                }
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
            // Reclaim ownership to each key's commit winner FIRST: rollback only reverts a
            // key while the failed survivor still owns its token, so a coalesced-out same-batch
            // loser holding the token would otherwise leave the key permanently dirty, serving
            // its never-persisted optimistic value (plaintext under ENCRYPTED) all session.
            reclaimBatchOwnershipToSurvivors(batch, finalByKey.values)
            // Roll back the optimistic cache for every key in this batch so
            // reads stop serving never-persisted values, then surface the
            // failure — processBatch fails all awaiters and logs.
            rollbackOptimisticState(finalByKey.values)
            throw e
        }
    }

    // Reclaim ownership to each key's commit winner so the post-commit cache re-assert below
    // isn't gated out by a coalesced-out same-batch loser that still holds the token.
    reclaimBatchOwnershipToSurvivors(batch, finalByKey.values)

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
                    val base64 = KSafeBase64.encode(encryptedCiphertext[op.userKey]!!)
                    memoryCache.replaceIf(op.rawCacheKey, op.jsonString, base64)
                    base64
                } else {
                    op.jsonString
                }
                if (writeOwners[op.userKey] === op.writeToken) {
                    val protLiteral = KeySafeMetadataManager.protectionToLiteral(op.protection)
                    val meta = encMetaForWrite(op.protection, op.requireUnlockedDevice, op.keyGeneration)
                    // A clamped write's enqueue-time optimistic meta still names the stale
                    // generation; swap it for the committed one so reads derive the alias
                    // and AAD the entry was actually written with. CAS keeps a newer
                    // writer's meta untouched.
                    clampRepairs[op.userKey]?.let { (stale, clamped) ->
                        encMetaMap.replaceIf(op.userKey, stale, clamped)
                    }
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
                    // `||` short-circuits, so removeIf still runs its side effect first and
                    // containsKey is consulted only when it found nothing to remove.
                    if (writeOwners[op.userKey] !== op.writeToken &&
                        (memoryCache.removeIf(op.rawCacheKey, cacheValue) ||
                            !memoryCache.containsKey(op.rawCacheKey))
                    ) {
                        protectionMap.removeIf(op.userKey, protLiteral)
                        encMetaMap.removeIf(op.userKey, meta)
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
                if (writeOwners[op.userKey] !== op.writeToken &&
                    (memoryCache.removeIf(op.rawCacheKey, op.value) ||
                        !memoryCache.containsKey(op.rawCacheKey))
                ) {
                    protectionMap.removeIf(op.userKey, protLiteral)
                }
            }
            is PendingWrite.Rotate -> if (op.userKey in appliedRotations) {
                op.applied.set(true)
                val newBase64 = KSafeBase64.encode(encryptedCiphertext[op.userKey]!!)
                // Prove the entry untouched before bumping RAM meta. Ciphertext-at-rest
                // caches CAS on the unique pre-rotation ciphertext. A plaintext-policy
                // cache holds the decoded value (never the old ciphertext), so that CAS
                // can never match and RAM meta went stale for the whole session; anchor
                // on write ownership instead — rotation never claims a key, so an
                // unchanged owner token means no user write claimed the key since the
                // rotation read it (re-checked below).
                val swapped = if (cacheHoldsCiphertext || op.requireUnlockedDevice) {
                    memoryCache.replaceIf(op.rawCacheKey, op.expectedOldCiphertext, newBase64)
                } else {
                    writeOwners[op.userKey] === op.ownerTokenAtIssue &&
                        memoryCache[op.rawCacheKey] == op.jsonString
                }
                // Bump the in-memory meta ONLY when the entry was proven untouched. If an
                // optimistic write intervened, RAM meta is left alone: the DISK meta is
                // already correct, and stamping the new generation over a concurrent
                // write's meta would point its reads at the wrong key.
                if (swapped) {
                    encMetaMap[op.userKey]
                        ?.takeIf {
                            it.keyGeneration < op.keyGeneration &&
                                it.requireUnlockedDevice == op.requireUnlockedDevice
                        }
                        ?.let { old ->
                            val bumped =
                                encMetaForWrite(op.protection, op.requireUnlockedDevice, op.keyGeneration)
                            encMetaMap.replaceIf(op.userKey, old, bumped)
                            // Ownership re-check (plaintext-policy path): a write that
                            // claimed the key between the check and the bump had set its
                            // own value-equal old meta — restore it so its routing wins.
                            if (!cacheHoldsCiphertext && !op.requireUnlockedDevice &&
                                writeOwners[op.userKey] !== op.ownerTokenAtIssue
                            ) {
                                encMetaMap.replaceIf(op.userKey, bumped, old)
                            }
                        }
                }
            }
            is PendingWrite.SetKeyGeneration -> {
                // Monotonic, matching updateCache's snapshot load.
                currentKeyGeneration.raiseToAtLeast(op.generation)
                if (op in appliedGenerationWrites) op.applied.set(true)
            }
            // The in-progress flag is not cached; startup/manual resume always reads the
            // durable key-generation record. No in-memory maintenance is needed here.
            is PendingWrite.CompleteKeyRotation -> Unit
            is PendingWrite.SweepSupersededMasters -> {
                // Serialized on the consumer: every earlier write is committed and no
                // batch is concurrently encrypting, so "unreferenced on disk" really
                // means unreferenced. A skipped (still-old-generation) entry keeps its
                // master alive via its metadata reference.
                val postSnapshot = storage.snapshot()
                // Resolve the set of master aliases STILL referenced by a surviving DEFAULT
                // entry, keyed by the PHYSICAL alias — not by the (unlockPolicy, generation)
                // pair. On JVM/Web both unlock policies collapse onto ONE physical master
                // alias (masterAlias ignores the flag), so a per-pair check would let the
                // `true` iteration delete the exact key the `false` iteration preserved for a
                // surviving relaxed entry. The empty-string user key IS a valid DEFAULT key
                // and its master must be counted like any other.
                val referencedAliases = mutableSetOf<String>()
                for ((rawKey, storedValue) in postSnapshot) {
                    val userKey = KeySafeMetadataManager.tryExtractCanonicalMetadataKey(rawKey) ?: continue
                    val rawMeta = (storedValue as? StoredValue.Text)?.value ?: continue
                    val protection = KeySafeMetadataManager.parseProtection(rawMeta) ?: continue
                    if (protection != KSafeProtection.DEFAULT) continue
                    if (KeySafeMetadataManager.parseEnvelopeVersion(rawMeta) <
                        KeySafeMetadataManager.ENVELOPE_VERSION_V2
                    ) continue
                    // A metadata record whose value never landed (a torn write on a backend
                    // without multi-key atomicity) describes nothing decryptable, but counting it
                    // would keep its generation's master alive forever: rotation skips it for
                    // lack of ciphertext and the orphan sweep enumerates value records, so no
                    // later pass can ever release the reference.
                    if (!hasAnyValueRecord(postSnapshot, userKey)) continue
                    referencedAliases += aliasWithGeneration(
                        masterAlias(KeySafeMetadataManager.parseRequireUnlockedDevice(rawMeta)),
                        KeySafeMetadataManager.parseKeyGeneration(rawMeta),
                    )
                }
                val candidateAliases = mutableSetOf<String>()
                for (requireUnlocked in listOf(false, true)) {
                    for (generation in 1 until op.newGeneration) {
                        candidateAliases += aliasWithGeneration(masterAlias(requireUnlocked), generation)
                    }
                }
                for (alias in candidateAliases) {
                    if (alias in referencedAliases) continue
                    deleteEngineKeyBestEffort(
                        alias,
                        attempt = "rotation sweep could not delete superseded master",
                        consequence = "ignored; retried by the next rotation's sweep",
                    )
                }
            }
            // A delete's desired in-memory state IS the wiped state.
            is PendingWrite.Delete, is PendingWrite.ClearAll -> Unit
        }
    }

    // Best-effort per-entry key cleanup, run AFTER the commit (a failure must not fail an
    // already-persisted batch) and AFTER the post-commit meta maintenance above, so the
    // live set below reflects the batch's own rotations. Guarded against that live set:
    // no scheduled deletion may destroy an alias some CURRENT entry still resolves to (a
    // generation-suffix or dotted-key coincidence would otherwise let one entry's cleanup
    // take another entry's key with it — unrecoverable for hardware-backed keys).
    if (aliasesToDelete.isNotEmpty()) {
        val liveAliases = mutableSetOf<String>()
        for ((liveKey, literal) in protectionMap.snapshot()) {
            val prot = KeySafeMetadataManager.parseProtection(literal) ?: continue
            liveAliases += aliasForRead(liveKey, prot)
        }
        for (alias in aliasesToDelete) {
            if (alias in liveAliases) continue
            deleteEngineKeyBestEffort(
                alias,
                attempt = "could not delete superseded engine key",
                consequence = "ignored; key material may remain in the platform vault",
            )
        }
    }

    // Per-op encrypt failures: successful ops are already committed; roll back the dropped
    // keys' optimistic cache BEFORE failing their awaiters, so a caller that catches the
    // exception and immediately re-reads sees the reverted value, not the phantom.
    if (encryptFailures.isNotEmpty()) {
        rollbackOptimisticState(finalByKey.values.filter { it.userKey in encryptFailures })
        // Fail EVERY superseded same-key op for a failed key — value writes AND deletes — not
        // just the coalesced survivor. When the survivor's encrypt fails, the batch commits no
        // storage op for that key, so its pre-batch disk value survives and the optimistic cache
        // is rolled back to it: nothing the batch intended for that key became durable. A
        // superseded value write completed with Unit would tell a caller its value is durable
        // when it's gone; a superseded delete completed with Unit is the same lie in reverse —
        // it reports the key removed while the old value survives on disk. Rotate (retried on the
        // next pass) and ClearAll are exempt.
        for (op in batch) {
            if (op is PendingWrite.Rotate || op is PendingWrite.ClearAll) continue
            val cause = encryptFailures[op.userKey] ?: continue
            op.completion?.completeExceptionally(cause)
            op.onWriteFailed?.let { cb -> runCatching { cb(cause) } }
        }
        val sample = encryptFailures.entries.first()
        ksafeLogError(
            "KSafe SEVERE: ${encryptFailures.size} encrypted write(s) failed and " +
                "were rolled back (other writes in the batch committed); e.g. " +
                "key='${sample.key}' (${sample.value::class.simpleName}: " +
                "${sample.value.message}). Awaiting callers received the exception."
        )
    }
    // Successful-write dirty flags are deliberately NOT cleared: they keep
    // stale collector snapshots from clobbering optimistic writes.
}
