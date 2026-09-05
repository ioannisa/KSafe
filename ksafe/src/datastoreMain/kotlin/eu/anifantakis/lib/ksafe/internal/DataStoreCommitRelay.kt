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
 * Read side shared by every `DataStore`-backed [KSafePlatformStorage]. `.data` alone drops a write
 * whose commit raced the collection's first read, so [publish] re-broadcasts every commit here.
 */
internal class DataStoreCommitRelay<T>(
    private val dataStore: DataStore<T>,
    private val toStoredMap: (T) -> Map<String, StoredValue>,
) {
    private class Stamped<T>(val sequence: Int, val value: T)

    private val commitSequence = KSafeAtomicInt(0)

    // Replay 1 + DROP_OLDEST: emit never suspends, and a subscriber landing just after a commit
    // still receives it instead of waiting on `.data`.
    private val localCommits = MutableSharedFlow<Stamped<T>>(
        replay = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    suspend fun snapshot(): Map<String, StoredValue> = toStoredMap(dataStore.data.first())

    fun snapshotFlow(): Flow<Map<String, StoredValue>> = flow {
        // Read before merge subscribes, so it precedes the store read behind the first emission.
        val sequenceWhenStoreReadBegan = commitSequence.get()
        var newestDelivered = sequenceWhenStoreReadBegan
        var storeEmissions = 0

        merge(
            localCommits,
            dataStore.data.map { value ->
                // Only the first emission can predate a commit made during this collection.
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
