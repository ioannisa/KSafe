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

            while (batch.size < maxBatchSize) {
                val next = writeChannel.tryReceive().getOrNull() ?: break
                batch.add(next)
            }

            // An awaiting put skips the coalesce window so it completes in one round-trip.
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
                    // Awaiters already failed inside processBatch; this log is for fire-and-forget writes.
                    ksafeLogError(
                        "KSafe SEVERE: processBatch failed " +
                            "(${e::class.simpleName}: ${e.message}); " +
                            "dropped ${batch.size} fire-and-forget write(s)."
                    )
                }
            batch.clear()
        }
        } finally {
            // Writes already pulled off the channel would leave their awaiters hung forever.
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
        // One mutex per physical store, so a sibling instance's commit, clearAll or rotation sweep
        // cannot interleave here. Completions fire after processBatchBody, so no cross-instance wait.
        commitMutex.withLock {
            processBatchBody(batch)
        }
    } catch (e: Throwable) {
        if (e is CancellationException) {
            deferreds.forEach { it.cancel(e) }
            throw e
        }
        failure = e
    }

    if (failure != null) {
        deferreds.forEach { it.completeExceptionally(failure) }
        // Fire-and-forget callers have no deferred; runCatching so one cannot wedge the consumer.
        val cause: Throwable = failure
        batch.forEach { op -> op.onWriteFailed?.let { cb -> runCatching { cb(cause) } } }
        throw failure
    } else {
        deferreds.forEach { it.complete(Unit) }
    }
}

internal suspend fun KSafeCore.processBatchBody(batch: List<PendingWrite>) {
    // The last ClearAll is a batch boundary: only writes after it survive, so an earlier put
    // cannot resurrect wiped data.
    val lastClear = batch.indexOfLast { it is PendingWrite.ClearAll }
    if (lastClear >= 0) {
        try {
            performClearAll()
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
            // Nothing in this batch is durable, so both sides of the boundary roll back.
            reclaimBatchOwnershipToSurvivors(batch, batch)
            rollbackOptimisticState(batch)
            throw e
        }
        val after = batch.subList(lastClear + 1, batch.size)
        if (after.isNotEmpty()) processWrites(after)
        return
    }
    processWrites(batch)
}

internal fun KSafeCore.reclaimBatchOwnershipToSurvivors(
    batch: Collection<PendingWrite>,
    survivors: Collection<PendingWrite>,
) {
    // writeOwners is claimed in caller-thread order but the winner is chosen in channel order, so a
    // coalesced-out loser can still hold the key's token and wedge it; a later batch's token is left alone.
    val batchTokens = batch.mapTo(HashSet<Any>()) { it.writeToken }
    for (op in survivors) {
        val current = writeOwners[op.userKey] ?: continue
        if (current !== op.writeToken && current in batchTokens) {
            writeOwners.replaceIf(op.userKey, current, op.writeToken)
        }
    }
}

private class RolledBackSlots(
    val userKey: String,
    val rawCacheKey: String,
    val cachedValue: Any?,
    val protectionLiteral: String?,
    val meta: KSafeCore.EncMeta?,
)

internal suspend fun KSafeCore.rollbackOptimisticState(failedOps: Collection<PendingWrite>) {
    val rolledBack = mutableListOf<RolledBackSlots>()
    for (op in failedOps) {
        val key = op.userKey
        // Read before the release: a newer writer claims ownership before it stages anything.
        val cachedValue = memoryCache[op.rawCacheKey]
        val protectionLiteral = protectionMap[key]
        val meta = encMetaMap[key]
        // CAS, not read-then-clear: a newer write claims the key before adding its dirty flag, so
        // a stale read here would strip flags that write has already added.
        if (!writeOwners.removeIf(key, op.writeToken)) continue
        rolledBack += RolledBackSlots(key, op.rawCacheKey, cachedValue, protectionLiteral, meta)
        dirtyKeys.remove(valueRawKey(key))
        dirtyKeys.remove(legacyEncryptedRawKey(key))
        dirtyKeys.remove(key)
        // updateCache does not manage plaintextCache, so evict here too, or the timed and lazy
        // policies keep serving the phantom from the side cache.
        plaintextCache.remove(legacyEncryptedRawKey(key))
        plaintextCache.remove(key)
    }
    if (rolledBack.isEmpty()) return
    runCatching {
        // Epoch BEFORE snapshot — the argument-order default would read it after.
        val epoch = clearEpoch.get()
        updateCache(storage.snapshot(), epoch)
    }
        .onFailure {
            if (it is CancellationException) throw it
            // The re-merge never reached the disk, so drop what the failed write staged and let
            // the next merge repopulate. Metadata drops only when its value drop won the CAS.
            for (slot in rolledBack) {
                val dropped = slot.cachedValue != null &&
                    memoryCache.removeIf(slot.rawCacheKey, slot.cachedValue)
                if (!dropped && memoryCache.containsKey(slot.rawCacheKey)) continue
                slot.protectionLiteral?.let { literal ->
                    protectionMap.removeIf(slot.userKey, literal)
                }
                slot.meta?.let { m -> encMetaMap.removeIf(slot.userKey, m) }
            }
        }
}
