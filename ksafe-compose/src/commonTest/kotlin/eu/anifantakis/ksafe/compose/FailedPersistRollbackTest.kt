@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package eu.anifantakis.ksafe.compose

import androidx.compose.runtime.SnapshotMutationPolicy
import androidx.compose.runtime.neverEqualPolicy
import androidx.compose.runtime.structuralEqualityPolicy
import eu.anifantakis.lib.ksafe.compose.KSafeComposeState
import eu.anifantakis.lib.ksafe.compose.observeFromStorage
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: when a persist fails, the rollback fires for every write that still owns the visible
 * value — in every mode the module offers — and for no write that has been superseded. It once
 * hung off the write-echo latch, which suppresses stale flow emissions: that latch stays down for
 * a write netting back to the last synced value, and a timeout releases it mid-flight.
 */
class FailedPersistRollbackTest {

    /**
     * The saver records each write's token on the setter's own stack, as the real savers do, so a
     * test reconciles the write it means rather than whatever is armed later.
     */
    private fun newState(
        initial: String = "A",
        policy: SnapshotMutationPolicy<String> = structuralEqualityPolicy(),
        writeTokens: MutableList<Long> = mutableListOf(),
    ): KSafeComposeState<String> {
        lateinit var state: KSafeComposeState<String>
        state = KSafeComposeState(
            initialValue = initial,
            valueSaver = { writeTokens += state.writeTokenInFlight() },
            policy = policy,
        )
        return state
    }

    /**
     * The module's default configuration (no scope, observeExternalChanges = false) never advances
     * the last-synced baseline, so a toggle back to the starting value looks like no write at all.
     */
    @Test
    fun failedPersist_ofAWriteBackToTheStartingValue_rollsBack() {
        val tokens = mutableListOf<Long>()
        val state = newState("A", writeTokens = tokens)

        state.value = "B" // reaches storage
        state.value = "A" // toggled back; this is the write whose persist fails

        state.reconcileAfterFailedPersist(tokens.last(), durableValue = "B")

        assertEquals(
            "B", state.value,
            "a write that happens to match the starting value is still a write: when its persist " +
                "fails the state must show the durable value, not the phantom",
        )
    }

    /** The timeout backstop drops the echo latch while the write is still unresolved. */
    @Test
    fun failedPersist_arrivingAfterTheWriteEchoTimeout_rollsBack() = runTest {
        val tokens = mutableListOf<Long>()
        val state = newState("A", writeTokens = tokens)
        val flow = MutableSharedFlow<String>(replay = 0)
        val timeout = 1_000L

        val job = launch {
            state.observeFromStorage(
                flow = flow,
                coldStart = false,
                observeExternalChanges = true,
                writeEchoTimeoutMs = timeout,
            )
        }
        advanceUntilIdle()

        state.value = "B"

        // Cross the backstop window with no emission at all: the latch drops while the write is
        // still unresolved. An emission here would resolve it and the test would pass for free.
        advanceTimeBy(timeout + 1)
        runCurrent()

        state.reconcileAfterFailedPersist(tokens.last(), durableValue = "A")

        assertEquals(
            "A", state.value,
            "a persist failure that lands after the echo backstop window must still revert the " +
                "value that never reached storage",
        )

        job.cancel()
    }

    /**
     * The rollback decides whether it still owns the state and then publishes; a write landing
     * between those two steps owns the state and must survive.
     */
    @Test
    fun failedPersist_rollback_doesNotClobberAWriteThatRacedIn() {
        val tokens = mutableListOf<Long>()
        val state = newState("A", writeTokens = tokens)

        state.value = "B"
        val failing = tokens.last()
        state.betweenGateAndPublishForTest = {
            state.betweenGateAndPublishForTest = null
            state.value = "C"
        }

        state.reconcileAfterFailedPersist(failing, durableValue = "A")

        assertEquals(
            "C", state.value,
            "a user write racing the rollback's publish must not be reverted to a durable value " +
                "that predates it",
        )
    }

    /**
     * A value cannot name a write: under a policy that fires the setter for every assignment, two
     * writes carry equal values and the first one's failure must not revert the second.
     */
    @Test
    fun failedPersist_ofASupersededWriteCarryingAnEqualValue_leavesTheLaterWriteAlone() {
        val tokens = mutableListOf<Long>()
        val state = newState("A", neverEqualPolicy(), tokens)

        state.value = "B" // this write's persist fails
        state.value = "B" // supersedes it, same value, still in flight

        state.reconcileAfterFailedPersist(tokens.first(), durableValue = "A")

        assertEquals(
            "B", state.value,
            "a superseded write's failure must not revert the write that replaced it just " +
                "because the two carry the same value",
        )
    }

    /**
     * A policy that equates nothing must not make the rollback unreachable — it once did, when
     * ownership was matched with the policy rather than with the write's own identity.
     */
    @Test
    fun failedPersist_underNeverEqualPolicy_rollsBack() {
        val tokens = mutableListOf<Long>()
        val state = newState("A", neverEqualPolicy(), tokens)

        state.value = "B"

        state.reconcileAfterFailedPersist(tokens.last(), durableValue = "A")

        assertEquals(
            "A", state.value,
            "the write is identified by its token, not by the recomposition policy",
        )
    }
}
