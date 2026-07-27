package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.DataStore
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.merge

/**
 * The read side shared by every `DataStore`-backed [KSafePlatformStorage]: it projects the store
 * through [toStoredMap] and re-broadcasts every commit passed to [publish] to [snapshotFlow]
 * collectors.
 *
 * DataStore's `.data` alone is not a reliable change source for a long-lived collection: a
 * collection whose first read races an in-flight write can be stamped with the writer's
 * already-incremented version while still reading the pre-write file (the version is bumped before
 * the file write), after which `.data`'s internal version filter drops that write's emission — the
 * collector observes the change only at the NEXT write, or never. Emitting the committed state
 * directly makes every same-storage write observable regardless. `.data` stays merged in for the
 * initial value and changes made outside this storage.
 *
 * Replay 1 + DROP_OLDEST: emit never suspends, a slow collector is conflated to the newest commit
 * (older whole-store snapshots are superseded by construction), and a collector whose subscription
 * lands just AFTER a racing commit's emit still receives that commit via the replay instead of
 * waiting on the poisoned `.data` filter.
 *
 * Merging leaves the two sources unordered, so both are stamped with a commit sequence and a
 * snapshot that is behind one already delivered is discarded. The stamp a `.data` emission carries
 * is the sequence read when its own read STARTED, which makes the discard lossless in both
 * directions: a commit published after that point is necessarily newer than anything the read can
 * return, while a read that started after a commit sees a file that write had already finished, so
 * it is authoritative even where it disagrees — which is how a change made outside this storage
 * still reaches collectors.
 */
internal class DataStoreCommitRelay<T>(
    private val dataStore: DataStore<T>,
    private val toStoredMap: (T) -> Map<String, StoredValue>,
) {
    private class Stamped<T>(val sequence: Int, val value: T)

    private val commitSequence = KSafeAtomicInt(0)

    private val localCommits = MutableSharedFlow<Stamped<T>>(
        replay = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    suspend fun snapshot(): Map<String, StoredValue> = toStoredMap(dataStore.data.first())

    fun snapshotFlow(): Flow<Map<String, StoredValue>> = flow {
        // Read before merge subscribes, so it precedes the store read behind the first `.data`
        // emission. Everything below is per-collection state.
        val sequenceWhenStoreReadBegan = commitSequence.get()
        var newestDelivered = sequenceWhenStoreReadBegan
        var storeEmissions = 0

        merge(
            localCommits,
            dataStore.data.map { value ->
                // Only the first emission comes from a read that may predate a commit made
                // during this collection; every later one is produced BY a write and so
                // already carries that write.
                val sequence =
                    if (storeEmissions++ == 0) sequenceWhenStoreReadBegan else commitSequence.get()
                Stamped(sequence, value)
            },
        ).collect { stamped ->
            if (stamped.sequence < newestDelivered) return@collect
            newestDelivered = stamped.sequence
            emit(toStoredMap(stamped.value))
        }
    }

    /** Announces the state a write through the owning storage [committed]. */
    suspend fun publish(committed: T) {
        localCommits.emit(Stamped(nextCommitSequence(), committed))
    }

    private fun nextCommitSequence(): Int {
        while (true) {
            val current = commitSequence.get()
            if (commitSequence.compareAndSet(current, current + 1)) return current + 1
        }
    }
}
