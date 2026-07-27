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
 * value — in every mode the module offers — and for no write that has been superseded.
 *
 * The rollback used to be gated on the write-echo latch, which exists for a different job:
 * suppressing stale flow emissions while a write propagates. That latch is deliberately down
 * for a write that nets back to the last synced value, and a timeout releases it while the
 * write is still unresolved, so it was never a usable proxy for "this write is still in flight".
 * Each test below pins one mode in which the two concerns disagree.
 */
class FailedPersistRollbackTest {

    /**
     * The saver records each write's token exactly as the real ones do — on the setter's own
     * stack — so the tests reconcile the write they mean rather than whatever is armed later.
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
     * Without external observation nothing ever advances the last-synced baseline, so a toggle
     * flipped back to the value the state started with looks identical to that baseline while
     * storage has since moved on. Its persist failing must still roll the phantom back — this is
     * the module's DEFAULT configuration (no scope / observeExternalChanges = false).
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

    /**
     * With external observation a write that never echoes has its emission-suppression latch
     * released by the timeout backstop. The write is still unresolved at that point — storage
     * never changed — so a failure landing after the window must still roll it back.
     */
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
        // still unresolved. Feeding an emission here would resolve the write legitimately and the
        // test would pass for the wrong reason.
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
     * A value cannot name a write. Under a policy that fires the setter for every assignment,
     * two writes can carry equal values, and the first one's failure must not claim — and revert —
     * the second, which may still be on its way to disk.
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
