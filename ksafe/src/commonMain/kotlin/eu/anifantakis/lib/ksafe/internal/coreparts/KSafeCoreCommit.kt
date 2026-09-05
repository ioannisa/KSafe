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

/** One entry's committed state as one unit: a legacy record left beside the canonical one reads
 *  back first and ignores the metadata that routes the decrypt. */
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

private fun KSafeCore.encryptedEntryRecordOps(op: EncryptingWrite, base64: String): List<StorageOp> =
    entryRecordOps(
        op.userKey,
        StoredValue.Text(base64),
        buildMetaJson(op.protection, op.requireUnlockedDevice, op.keyGeneration),
    )

/** Moves a sibling core's cached entry onto a committed rotation, or it keeps decrypting through a
 *  master the sweep will reclaim. CAS'd, so the sibling's own writes survive. */
private fun KSafeCore.adoptRotatedEntry(op: PendingWrite.Rotate, newBase64: String) {
    val ownerAtStart = writeOwners[op.userKey]
    val old = encMetaMap[op.userKey] ?: return
    if (old.keyGeneration >= op.keyGeneration ||
        old.requireUnlockedDevice != op.requireUnlockedDevice ||
        KeySafeMetadataManager.parseProtection(protectionMap[op.userKey]) != op.protection
    ) return
    val adopted = if (cacheHoldsCiphertext || op.requireUnlockedDevice) {
        memoryCache.replaceIf(op.rawCacheKey, op.expectedOldCiphertext, newBase64)
    } else {
        memoryCache[op.rawCacheKey] == op.jsonString
    }
    if (adopted) {
        val bumped = encMetaForWrite(op.protection, op.requireUnlockedDevice, op.keyGeneration)
        encMetaMap.replaceIf(op.userKey, old, bumped)
        // A write that claimed the key mid-adopt set a value-equal meta; hand its routing back.
        if (writeOwners[op.userKey] !== ownerAtStart) encMetaMap.replaceIf(op.userKey, bumped, old)
    }
}

/** Aliases this core's cache still decrypts through — its dirty writes may lag disk — so reaping
 *  one defaults every value it holds. */
private fun KSafeCore.inUseAliases(): Set<String> {
    val protections = protectionMap.snapshot()
    val aliases = mutableSetOf<String>()
    for ((userKey, meta) in encMetaMap.snapshot()) {
        val protection = KeySafeMetadataManager.parseProtection(protections[userKey]) ?: continue
        aliases += aliasForRawMeta(userKey, protection, meta)
    }
    return aliases
}

internal suspend fun KSafeCore.processWrites(batchIn: List<PendingWrite>) {
    // Disk holds the authoritative generation; the local atomic only caches it. Re-read it while
    // unreconciled, on any generation write, and — lazyLoad has no collector to see a sibling's
    // rotation — on every lazyLoad batch that encrypts, or keys mint under a superseded generation.
    var persistedKeygenRaw: String? = null
    val refreshForLazyEncrypt = lazyLoad && batchIn.any { it is EncryptingWrite }
    if (!keyGenerationReconciled.get() ||
        refreshForLazyEncrypt ||
        batchIn.any {
            it is PendingWrite.SetKeyGeneration || it is PendingWrite.CompleteKeyRotation
        }
    ) {
        // Outside the commit's own try/catch: a failure here must still roll back the optimistic
        // cache, or reads serve never-persisted values for the rest of the process lifetime.
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

    // Clamp user writes onto the store generation in BOTH directions: above it an entry is exiled
    // from every future rotation and clearAll sweep, below it a rotated store's entry drops back to
    // a v2 envelope. Rotate ops carry their own target generation and are fenced separately.
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

    // Coalesce to the LAST write per userKey; this also stops a same-batch delete+put from both
    // running, which would orphan the just-written entry's per-entry key.
    val finalByKey = LinkedHashMap<String, PendingWrite>()
    for (op in batch) {
        // A Rotate never displaces a same-batch user op: its CAS compares against pre-write disk
        // state, so it would pass and commit a re-encryption of the erased value.
        if (op is PendingWrite.Rotate && finalByKey.containsKey(op.userKey)) continue
        val existing = finalByKey[op.userKey]
        // Two generation records: the higher wins regardless of queue order, or a later, lower
        // adoption write displaces a rotation bump while both awaiters are acknowledged; at a tie
        // the in-progress bump wins.
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
        // A displaced write's superseded-alias captures must survive coalescing: it saw the
        // pre-transition alias the winner never did. The live-alias guard filters the rest.
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

    // Per-op failure isolation: a coalesced batch mixes unrelated keys, so one failing encrypt must
    // not cancel its siblings — hence captured Results rather than awaitAll's fail-fast.
    val encryptFailures = LinkedHashMap<String, Throwable>()
    if (toEncrypt.isNotEmpty()) {
        val gate = Semaphore(maxParallelEncrypts)
        val results = coroutineScope {
            toEncrypt.map { op ->
                async {
                    gate.withPermit {
                        val alias = aliasForWrite(op.userKey, op.protection, op.requireUnlockedDevice, op.keyGeneration)
                        // Generation-1 writes stay v2 (no AAD) so an un-rotated store stays
                        // byte-compatible with older releases; v3 authenticates identity + metadata.
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

    val rotateDiskSnapshot: Map<String, StoredValue>? =
        if (finalByKey.values.any { it is PendingWrite.Rotate }) storage.snapshot() else null
    // Fold the persisted generation in, so the Rotate fence below sees a sibling's rotation.
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
                // A plain value replacing ciphertext must reclaim the superseded platform key:
                // the store's inventory forgets it, so no later clearAll can ever find it.
                if (op.supersededPerEntryGeneration > 0) {
                    aliasesToDelete += perEntryAliasesThrough(
                        key, op.supersededPerEntryGeneration, op.supersededStrictAlias,
                    )
                }
            }
            is PendingWrite.Encrypted -> {
                // Encrypt failed: excluded here, awaiters failed and cache rolled back below.
                if (op.userKey in encryptFailures) continue
                val key = op.userKey
                val ciphertext = encryptedCiphertext[key]!!
                ops += encryptedEntryRecordOps(op, KSafeBase64.encode(ciphertext))
                // Old per-entry aliases are reclaimed only AFTER the commit, and re-compared
                // against the alias actually used — the clamp may have landed back on it.
                if (op.supersededAliases.isNotEmpty()) {
                    val usedAlias = aliasForWrite(key, op.protection, op.requireUnlockedDevice, op.keyGeneration)
                    op.supersededAliases.filterTo(aliasesToDelete) { it != usedAlias }
                }
            }
            is PendingWrite.Rotate -> {
                if (op.userKey in encryptFailures) continue
                val key = op.userKey
                val diskCiphertext =
                    (rotateDiskSnapshot?.get(valueRawKey(key)) as? StoredValue.Text)?.value
                        ?: (rotateDiskSnapshot?.get(legacyEncryptedRawKey(key)) as? StoredValue.Text)?.value
                // Fence: a clearAll or a sibling's rotation moved the store off this pass's target
                // generation, and stamping it on now would exile the entry from later passes.
                val fenced = op.expectedClearEpoch != clearEpoch.get() ||
                    currentKeyGeneration.get() != op.keyGeneration
                // CAS: commit only while disk still holds exactly what this rotation decrypted.
                // A write queued behind this batch needs no check — it overwrites later anyway.
                if (fenced || diskCiphertext != op.expectedOldCiphertext) {
                    // Reclaim the old per-entry alias only when disk no longer resolves to it: a
                    // write issued during the bump window re-encrypts under that SAME alias, and
                    // HARDWARE_ISOLATED has no software fallback, so deleting it would lose data.
                    val curMeta = (rotateDiskSnapshot?.get(metaRawKey(key)) as? StoredValue.Text)?.value
                    val curAliasInUse = KeySafeMetadataManager.parseProtection(curMeta)?.let { prot ->
                        // The RECORDED metadata's alias, not aliasForWrite: a legacy strict
                        // entry still reads from the bare alias.
                        aliasForRawMeta(key, prot, encMetaFromRaw(curMeta))
                    }
                    op.oldAliasToDelete?.let { oldAlias ->
                        if (curAliasInUse != oldAlias) aliasesToDelete += oldAlias
                    }
                    // The encrypt already minted the target-generation key; skipping the commit
                    // would strand it in the vault forever, so reclaim it (per-entry only).
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
                // Never write a generation below what a sibling persisted. At the same generation
                // write only to adopt a legacy record, repair a missing timestamp, or claim a
                // retry — never to re-stamp, which would reset the MaxAge clock. A clearAll removes
                // the record entirely, so its reset still passes.
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
                // Generation-CAS'd: a stale or fenced pass must not acknowledge a newer generation
                // as completed. Writing only from the in-progress state keeps retries idempotent.
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
            // No storage ops: the sweep runs post-commit, against a snapshot of durable state.
            is PendingWrite.SweepSupersededMasters -> Unit
            is PendingWrite.Delete -> {
                val key = op.userKey
                ops += StorageOp.Delete(valueRawKey(key))
                ops += StorageOp.Delete(key)
                ops += StorageOp.Delete(metaRawKey(key))
                ops += StorageOp.Delete(legacyEncryptedRawKey(key))
                ops += StorageOp.Delete(legacyProtectionRawKey(key))
                // Sweep engine keys only when the entry provably used a per-entry alias: otherwise
                // the derived alias may be another store's live key, not a harmless no-op.
                if (op.usedPerEntryAlias) {
                    aliasesToDelete += perEntryAliasesThrough(key, op.keyGeneration, op.usedStrictAlias)
                }
            }
            // Handled as a batch boundary in processBatchBody; here only for exhaustiveness.
            is PendingWrite.ClearAll -> Unit
        }
    }

    if (ops.isNotEmpty()) {
        try {
            storage.applyBatch(ops)
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
            // Reclaim ownership to each key's commit winner FIRST: rollback only reverts a key
            // whose survivor still owns its token, so a coalesced-out loser holding it would
            // leave the key permanently dirty on a never-persisted value.
            reclaimBatchOwnershipToSurvivors(batch, finalByKey.values)
            rollbackOptimisticState(finalByKey.values)
            throw e
        }
    }

    postApplyBatchHook?.invoke(finalByKey.keys) // test-only interleaving seam; null in production

    // Ownership goes to the commit winner, or a coalesced-out loser gates out the re-assert below.
    reclaimBatchOwnershipToSurvivors(batch, finalByKey.values)

    // Post-commit maintenance: ciphertext-at-rest policies swap plaintext → ciphertext under an
    // ownership gate, then re-assert state a concurrent clearAll may have wiped (putIfAbsent, so a
    // newer write's value stays untouched).
    for (op in finalByKey.values) {
        when (op) {
            is PendingWrite.Encrypted -> if (op.userKey !in encryptFailures) {
                // Strict entries settle to ciphertext even under a plaintext policy, so reads
                // enforce the lock. Gated on OWNERSHIP, not value: writers stage identical strings.
                val owns = writeOwners[op.userKey] === op.writeToken
                val cacheValue: Any = if (cacheHoldsCiphertext || op.requireUnlockedDevice) {
                    val base64 = KSafeBase64.encode(encryptedCiphertext[op.userKey]!!)
                    if (owns) {
                        memoryCache.replaceIf(op.rawCacheKey, op.jsonString, base64)
                        // Token flipped mid-swap: give the newer writer its plaintext back.
                        if (writeOwners[op.userKey] !== op.writeToken) {
                            memoryCache.replaceIf(op.rawCacheKey, base64, op.jsonString)
                        }
                    }
                    base64
                } else {
                    op.jsonString
                }
                if (owns) {
                    val protLiteral = KeySafeMetadataManager.protectionToLiteral(op.protection)
                    val meta = encMetaForWrite(op.protection, op.requireUnlockedDevice, op.keyGeneration)
                    // A clamped write's enqueue-time meta still names the stale generation; swap in
                    // the committed one so reads derive the alias and AAD it was written with.
                    clampRepairs[op.userKey]?.let { (stale, clamped) ->
                        encMetaMap.replaceIf(op.userKey, stale, clamped)
                    }
                    memoryCache.putIfAbsent(op.rawCacheKey, cacheValue)
                    postCommitRepairHook?.invoke(op.userKey) // test-only interleaving seam; null in production
                    protectionMap.putIfAbsent(op.userKey, protLiteral)
                    encMetaMap.putIfAbsent(op.userKey, meta)
                    // TOCTOU guard: if ownership was lost since the check, undo what this op
                    // restored — coupled to the cache value, so a newer PUT keeps its metadata and
                    // a DELETE's resurrected orphans are dropped (`||` runs removeIf's effect first).
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
                // TOCTOU guard, same two-path cleanup as the Encrypted branch.
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
                // Prove the entry untouched before bumping RAM meta: a plaintext-policy cache never
                // holds the old ciphertext, so its CAS can never match — anchor on write ownership
                // instead, since rotation never claims a key.
                val swapped = if (cacheHoldsCiphertext || op.requireUnlockedDevice) {
                    memoryCache.replaceIf(op.rawCacheKey, op.expectedOldCiphertext, newBase64)
                } else {
                    writeOwners[op.userKey] === op.ownerTokenAtIssue &&
                        memoryCache[op.rawCacheKey] == op.jsonString
                }
                // Bump RAM meta only when the entry was proven untouched: disk meta is already
                // correct, and stamping over a concurrent write would misroute its reads.
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
                            // Ownership re-check: a write that claimed the key set its own
                            // value-equal old meta — restore it so its routing wins.
                            if (!cacheHoldsCiphertext && !op.requireUnlockedDevice &&
                                writeOwners[op.userKey] !== op.ownerTokenAtIssue
                            ) {
                                encMetaMap.replaceIf(op.userKey, bumped, old)
                            }
                        }
                }
                siblings?.others(this)?.forEach { it.adoptRotatedEntry(op, newBase64) }
            }
            is PendingWrite.SetKeyGeneration -> {
                currentKeyGeneration.raiseToAtLeast(op.generation)
                if (op in appliedGenerationWrites) op.applied.set(true)
            }
            // The in-progress flag is never cached; resume always reads the durable record.
            is PendingWrite.CompleteKeyRotation -> Unit
            is PendingWrite.SweepSupersededMasters -> {
                // Serialized on the consumer: every earlier write is committed and nothing is
                // concurrently encrypting, so a disk scan sees every live reference.
                val postSnapshot = storage.snapshot()
                // Keyed by the PHYSICAL alias: on JVM/Web both unlock policies collapse onto one
                // master, so a per-pair check would delete the key the other pass preserved.
                val referencedAliases = mutableSetOf<String>()
                for ((rawKey, storedValue) in postSnapshot) {
                    val userKey = KeySafeMetadataManager.tryExtractCanonicalMetadataKey(rawKey) ?: continue
                    val rawMeta = (storedValue as? StoredValue.Text)?.value ?: continue
                    val protection = KeySafeMetadataManager.parseProtection(rawMeta) ?: continue
                    if (protection != KSafeProtection.DEFAULT) continue
                    if (KeySafeMetadataManager.parseEnvelopeVersion(rawMeta) <
                        KeySafeMetadataManager.ENVELOPE_VERSION_V2
                    ) continue
                    // A metadata record whose value never landed describes nothing decryptable, but
                    // counting it would pin its generation's master alive forever.
                    if (!hasAnyValueRecord(postSnapshot, userKey)) continue
                    referencedAliases += aliasWithGeneration(
                        masterAlias(KeySafeMetadataManager.parseRequireUnlockedDevice(rawMeta)),
                        KeySafeMetadataManager.parseKeyGeneration(rawMeta),
                    )
                }
                // Another live core on this store may still route through an older master —
                // its own writes are dirty, so no snapshot can show them.
                siblings?.others(this)?.forEach { referencedAliases += it.inUseAliases() }
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
            // A delete wants the wiped state; nothing to re-assert.
            is PendingWrite.Delete, is PendingWrite.ClearAll -> Unit
        }
    }

    // Best-effort key cleanup, after the commit and after the meta maintenance above so the live
    // set reflects this batch's rotations: no deletion may destroy an alias a CURRENT entry still
    // resolves to, which for hardware-backed keys is unrecoverable.
    if (aliasesToDelete.isNotEmpty()) {
        val liveAliases = mutableSetOf<String>()
        for ((liveKey, literal) in protectionMap.snapshot()) {
            val prot = KeySafeMetadataManager.parseProtection(literal) ?: continue
            liveAliases += aliasForRead(liveKey, prot)
        }
        siblings?.others(this)?.forEach { liveAliases += it.inUseAliases() }
        for (alias in aliasesToDelete) {
            if (alias in liveAliases) continue
            deleteEngineKeyBestEffort(
                alias,
                attempt = "could not delete superseded engine key",
                consequence = "ignored; key material may remain in the platform vault",
            )
        }
    }

    // Roll back the dropped keys' optimistic cache BEFORE failing their awaiters, so a caller that
    // catches and immediately re-reads sees the reverted value, not the phantom.
    if (encryptFailures.isNotEmpty()) {
        rollbackOptimisticState(finalByKey.values.filter { it.userKey in encryptFailures })
        // Fail EVERY superseded same-key op, not just the coalesced survivor: nothing the batch
        // intended for that key became durable, so completing one with Unit reports a durability
        // that never happened. Rotate (retried next pass) and ClearAll are exempt.
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
    // Successful writes keep their dirty flags: they stop a stale collector snapshot from
    // clobbering an optimistic write.
}
