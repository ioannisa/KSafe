package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import eu.anifantakis.lib.ksafe.internal.DataStoreCommitRelay
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.Collections
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in the ordering contract of the snapshot flow the DataStore-backed storages expose:
 * a store read that began before a commit must never be delivered as the newer state, while
 * the commit re-broadcast and genuinely later store emissions both keep flowing.
 *
 * Drives [DataStoreCommitRelay] against a store whose `data` flow the test emits into by
 * hand, so every interleaving below is exact — no sleeps, no thread races.
 */
class JvmSnapshotFlowOrderingTest {

    /** A `DataStore` whose `data` is whatever the test emits; writes go through the relay. */
    private class ScriptedDataStore(
        private val emissions: MutableSharedFlow<Map<String, String>>,
    ) : DataStore<Map<String, String>> {
        override val data: Flow<Map<String, String>> get() = emissions
        override suspend fun updateData(
            transform: suspend (t: Map<String, String>) -> Map<String, String>,
        ): Map<String, String> = error("the test commits through the relay directly")
    }

    private fun relayFor(emissions: MutableSharedFlow<Map<String, String>>) =
        DataStoreCommitRelay(ScriptedDataStore(emissions)) { m ->
            m.mapValues { (_, v) -> StoredValue.Text(v) }
        }

    private fun text(vararg pairs: Pair<String, String>): Map<String, StoredValue> =
        pairs.associate { (k, v) -> k to StoredValue.Text(v) }

    private class Collected {
        val seen: MutableList<Map<String, StoredValue>> = Collections.synchronizedList(mutableListOf())
        lateinit var job: Job
    }

    private suspend fun CoroutineScope.collect(
        relay: DataStoreCommitRelay<Map<String, String>>,
        emissions: MutableSharedFlow<Map<String, String>>,
    ): Collected {
        val out = Collected()
        out.job = launch(Dispatchers.Default) { relay.snapshotFlow().collect { out.seen.add(it) } }
        // The store arm has actually started collecting — every emit below is therefore
        // delivered, and every ordering the test asserts is the one it set up.
        withTimeout(5.seconds) { emissions.subscriptionCount.first { it > 0 } }
        return out
    }

    private suspend fun Collected.awaitCount(n: Int) {
        withTimeout(5.seconds) { while (seen.size < n) delay(1) }
    }

    // ---- a read that predates the commit must not be applied over it ----------------------

    @Test
    fun storeReadThatPredatesACommit_isNotDeliveredAfterIt() = runBlocking {
        val emissions = MutableSharedFlow<Map<String, String>>(extraBufferCapacity = 16)
        val relay = relayFor(emissions)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val collected = scope.collect(relay, emissions)

        // A write commits while the store's own read is still in flight.
        relay.publish(mapOf("token" to "fresh"))
        collected.awaitCount(1)

        // The in-flight read now completes, carrying the PRE-commit file content.
        emissions.emit(mapOf("token" to "stale"))
        // A genuinely later store change, so the assertion below has a barrier to wait on
        // instead of a sleep — and so a fix that simply drops the store arm is caught.
        emissions.emit(mapOf("token" to "external"))
        collected.awaitCount(2)

        val seen = collected.seen.toList()
        assertEquals(text("token" to "fresh"), seen.first(), "the commit must be re-broadcast")
        assertTrue(
            text("token" to "stale") !in seen,
            "a store read taken before the commit was applied over it: $seen",
        )
        assertEquals(
            text("token" to "external"), seen.last(),
            "a store change made after the commit must still reach collectors: $seen",
        )

        collected.job.cancelAndJoin()
    }

    // ---- the store arm still seeds and still carries external changes ---------------------

    @Test
    fun withNoCommitYet_theStoresOwnReadIsDelivered() = runBlocking {
        val emissions = MutableSharedFlow<Map<String, String>>(extraBufferCapacity = 16)
        val relay = relayFor(emissions)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val collected = scope.collect(relay, emissions)

        emissions.emit(mapOf("token" to "on-disk"))
        collected.awaitCount(1)

        assertEquals(
            listOf(text("token" to "on-disk")), collected.seen.toList(),
            "with nothing committed through the relay, the store read IS the initial value",
        )

        collected.job.cancelAndJoin()
    }

    @Test
    fun aStoreReadTakenAfterTheCommit_isStillDelivered() = runBlocking {
        val emissions = MutableSharedFlow<Map<String, String>>(extraBufferCapacity = 16)
        val relay = relayFor(emissions)

        relay.publish(mapOf("token" to "committed"))

        // Subscribing AFTER the commit: this read cannot predate it, so it is authoritative
        // even though it disagrees with the last committed state.
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val collected = scope.collect(relay, emissions)
        collected.awaitCount(1)
        emissions.emit(mapOf("token" to "changed-elsewhere"))
        collected.awaitCount(2)

        assertEquals(
            text("token" to "changed-elsewhere"), collected.seen.toList().last(),
            "a read that began after the commit must win: ${collected.seen}",
        )

        collected.job.cancelAndJoin()
    }
}
