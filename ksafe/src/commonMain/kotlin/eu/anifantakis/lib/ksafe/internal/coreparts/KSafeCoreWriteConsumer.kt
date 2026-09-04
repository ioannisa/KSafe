package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.PendingWrite
import eu.anifantakis.lib.ksafe.internal.ksafeLogError
import kotlin.time.TimeSource
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlin.time.Duration.Companion.milliseconds

internal fun KSafeCore.startWriteConsumer() {
    writeScope.launch {
        val batch = mutableListOf<PendingWrite>()
        try {
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
                    // Poll, never park: a timer-cancelled receive drops an element already handed to it.
                    val next = writeChannel.tryReceive().getOrNull()
                    if (next == null) { delay(minOf(remaining, 2L).milliseconds); continue }
                    batch.add(next)
                    if (next.completion != null) break
                }
            }

            runCatching { processBatch(batch) }
                .onFailure { e ->
                    if (e is CancellationException) throw e
                    // Awaiters were already failed inside processBatch; this log is
                    // for fire-and-forget callers with no Deferred to listen on.
                    ksafeLogError(
                        "KSafe SEVERE: processBatch failed " +
                            "(${e::class.simpleName}: ${e.message}); " +
                            "dropped ${batch.size} fire-and-forget write(s)."
                    )
                }
            batch.clear()
        }
        } finally {
            // Cancelled mid-assembly: writes pulled into this batch but not yet processed
            // would otherwise leave their awaiters hung forever. Hand them the same
            // cancellation a still-queued write gets in cancel().
            if (batch.isNotEmpty()) {
                val cause = CancellationException("KSafe write consumer was cancelled")
                batch.forEach { it.completion?.cancel(cause) }
            }
        }
    }
}

internal suspend fun KSafeCore.processBatch(batch: List<PendingWrite>) {
    if (batch.isEmpty()) return

    val deferreds = batch.mapNotNull { it.completion }

    var failure: Throwable? = null
    try {
        // Serialized across same-file instances (the shared backend passes one mutex to
        // every core on the physical store): a sibling's encrypt→CAS-snapshot→commit,
        // clearAll, or rotation sweep can no longer interleave inside this batch's own
        // sequence. Within one instance the single consumer already serialized it, so a
        // private default mutex is free. Batches never await another instance's consumer
        // (completions fire after processBatchBody returns), so no deadlock path exists.
        commitMutex.withLock {
            processBatchBody(batch)
        }
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
        // Fire-and-forget callers have no deferred to fail; notify their callbacks (the
        // optimistic rollback already ran inside processWrites' catch). runCatching so a
        // callback can never wedge the write consumer.
        val cause: Throwable = failure
        batch.forEach { op -> op.onWriteFailed?.let { cb -> runCatching { cb(cause) } } }
        throw failure  // surfaces to startWriteConsumer's runCatching for logging
    } else {
        deferreds.forEach { it.complete(Unit) }
    }
}

internal suspend fun KSafeCore.processBatchBody(batch: List<PendingWrite>) {
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

/**
 * Reverts optimistic in-memory state for failed writes and reconciles the keys against
 * disk via [updateCache] (a previously-persisted value is restored, a never-persisted one
 * is evicted). Ownership gate: a failed op only rolls back a key it still OWNS
 * (`writeOwners[key] === op.writeToken`); a newer write for the same key now owns the dirty
 * flags and optimistic cache, so clearing them here would strip its state.
 */
internal fun KSafeCore.reclaimBatchOwnershipToSurvivors(
    batch: Collection<PendingWrite>,
    survivors: Collection<PendingWrite>,
) {
    // writeOwners is claimed in caller-thread order but the commit winner is chosen in channel
    // order, so a coalesced-out same-batch loser (e.g. a delete before the winning put) can still
    // own the key's token and gate the winner's cache re-assert / rollback out, wedging the key
    // for the session. Reclaim ownership to the winner via CAS; a live later-batch writer's token
    // isn't in this batch, so it's left untouched and the winner correctly yields to it.
    val batchTokens = batch.mapTo(HashSet<Any>()) { it.writeToken }
    for (op in survivors) {
        val current = writeOwners[op.userKey] ?: continue
        if (current !== op.writeToken && current in batchTokens) {
            writeOwners.replaceIf(op.userKey, current, op.writeToken)
        }
    }
}

internal suspend fun KSafeCore.rollbackOptimisticState(failedOps: Collection<PendingWrite>) {
    var rolledBackAny = false
    for (op in failedOps) {
        val key = op.userKey
        // Gate the clear on an ATOMIC ownership release (CAS), not a plain read-then-clear.
        // A newer caller-thread write B claims `writeOwners[key]` BEFORE it adds its dirty flag
        // / optimistic value; a non-atomic `if (writeOwners[key] !== token)` read could pass on
        // a stale value and then strip B's freshly-added flags. `removeIf` removes the entry
        // only while it still equals this failed op's token — so if B has already claimed, we
        // never owned it at this instant and skip B's state untouched (same CAS discipline the
        // post-commit repair uses). A failed op relinquishing ownership here is also correct: it
        // is no longer pending.
        if (!writeOwners.removeIf(key, op.writeToken)) continue
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
    runCatching {
        // Epoch BEFORE snapshot — the argument-order default would read it after.
        val epoch = clearEpoch.get()
        updateCache(storage.snapshot(), epoch)
    }
        .onFailure { if (it is CancellationException) throw it }
}
