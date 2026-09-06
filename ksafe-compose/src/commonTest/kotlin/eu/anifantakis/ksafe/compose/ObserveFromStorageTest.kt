@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package eu.anifantakis.ksafe.compose

import androidx.compose.runtime.structuralEqualityPolicy
import eu.anifantakis.lib.ksafe.compose.KSafeComposeState
import eu.anifantakis.lib.ksafe.compose.observeFromStorage
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: observeFromStorage's live/cold-start/warm-start lifecycle — external emissions reflect (even mid-echo-window), the user-write guard suppresses only the stale pre-write snapshot yet self-heals, and cold-start honors its timeout.
 */
class ObserveFromStorageTest {

    private fun newState(initial: String = "initial"): KSafeComposeState<String> =
        KSafeComposeState(
            initialValue = initial,
            valueSaver = { },
            policy = structuralEqualityPolicy(),
        )

    @Test
    fun observeFromStorage_liveMode_appliesUntilUserWrites_thenStopsClobbering() = runTest {
        val state = newState("initial")
        val flow = MutableSharedFlow<String>(replay = 0)

        val job = launch {
            state.observeFromStorage(
                flow = flow,
                coldStart = false,
                observeExternalChanges = true,
            )
        }
        advanceUntilIdle()

        flow.emit("first")
        advanceUntilIdle()
        assertEquals("first", state.value)

        flow.emit("second")
        advanceUntilIdle()
        assertEquals("second", state.value)

        state.value = "user_wrote"
        flow.emit("second")
        advanceUntilIdle()
        assertEquals("user_wrote", state.value, "the stale pre-write snapshot must not clobber the user's write")

        job.cancel()
    }

    @Test
    fun observeFromStorage_liveMode_resumesExternalReflection_afterEchoCatchesUp() = runTest {
        val state = newState("initial")
        val flow = MutableSharedFlow<String>(replay = 0)

        val job = launch {
            state.observeFromStorage(
                flow = flow,
                coldStart = false,
                observeExternalChanges = true,
            )
        }
        advanceUntilIdle()

        state.value = "user_wrote"

        flow.emit("initial")
        advanceUntilIdle()
        assertEquals("user_wrote", state.value)

        // The user's own write round-trips through disk, so the flow catches up.
        flow.emit("user_wrote")
        advanceUntilIdle()
        assertEquals("user_wrote", state.value)

        flow.emit("external_new")
        advanceUntilIdle()
        assertEquals(
            "external_new", state.value,
            "after the write's echo, newer external changes must reflect again",
        )

        state.value = "user_2"
        flow.emit("external_new")
        advanceUntilIdle()
        assertEquals("user_2", state.value, "a re-armed guard must suppress stale echoes again")

        job.cancel()
    }

    // A write whose echo never arrives (a persist that failed without a synchronous error, so storage
    // never changes and getFlow never re-emits) must not freeze observation forever.
    @Test
    fun observeFromStorage_liveMode_writeThatNeverEchoes_releasesLatchAfterTimeout() = runTest {
        val state = newState("initial")
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

        // Arm the latch; no matching echo will ever arrive.
        state.value = "user_wrote"

        flow.emit("initial")
        runCurrent()
        assertEquals("user_wrote", state.value, "the latch suppresses the pre-write snapshot before the window")

        advanceTimeBy(timeout + 1)
        runCurrent()

        // Proof the timeout released the latch: an armed latch would still suppress this exact value.
        flow.emit("initial")
        runCurrent()
        assertEquals("initial", state.value, "after the window, even the pre-write value must reflect")

        flow.emit("external_after")
        advanceUntilIdle()
        assertEquals(
            "external_after", state.value,
            "a write whose echo never arrives must not freeze observation past the timeout window",
        )

        job.cancel()
    }

    // A durable external change landing while the write-echo is in flight is a value the source flow
    // will never re-emit, so it must apply and clear the latch, not wait for the timeout backstop.
    @Test
    fun observeFromStorage_liveMode_externalChangeDuringEchoWindow_appliesImmediately() = runTest {
        val state = newState("A")
        val flow = MutableSharedFlow<String>(replay = 0)

        val job = launch {
            state.observeFromStorage(
                flow = flow,
                coldStart = false,
                observeExternalChanges = true,
            )
        }
        advanceUntilIdle()

        state.value = "B" // arms the latch; the echo is still in flight

        // Only runCurrent from here on (never advanceTimeBy/advanceUntilIdle): the value must
        // come from the emission itself, not from the timeout backstop releasing the latch.
        flow.emit("C")
        runCurrent()
        assertEquals("C", state.value, "a durable external change during the echo window must apply immediately")

        flow.emit("D")
        runCurrent()
        assertEquals("D", state.value, "later external changes must keep reflecting")

        job.cancel()
    }

    @Test
    fun observeFromStorage_liveMode_echoArrivingAfterExternalChange_stateTracksEmissionOrder() = runTest {
        val state = newState("A")
        val flow = MutableSharedFlow<String>(replay = 0)

        val job = launch {
            state.observeFromStorage(
                flow = flow,
                coldStart = false,
                observeExternalChanges = true,
            )
        }
        advanceUntilIdle()

        state.value = "B"

        flow.emit("C")
        runCurrent()
        assertEquals("C", state.value)

        flow.emit("B")
        runCurrent()
        assertEquals(
            "B", state.value,
            "with the latch cleared by the external change, the late echo applies like any emission",
        )

        // Observation stays live afterwards.
        flow.emit("E")
        runCurrent()
        assertEquals("E", state.value)

        job.cancel()
    }

    // updateFromFlow's guard check-then-apply isn't atomic against the setter, so a stale emission can clobber a write.
    // The user-write echo re-applies the value (self-heal), since distinctUntilChanged means no other emission would.
    @Test
    fun updateFromFlow_userWriteEcho_selfHealsAStaleClobber() {
        val state = newState("A")            // syncedValue = "A"
        state.value = "B"                     // arms the guard; _internalState = "B", lastUserWrite = "B"
        assertEquals("B", state.value)

        state.simulateStaleClobberForTest("A")
        assertEquals("A", state.value, "precondition: the stale emission diverged the visible state")

        state.updateFromFlow("B")

        assertEquals(
            "B", state.value,
            "the user-write echo must restore the value a stale emission clobbered; " +
                "before the fix it stayed stuck on the stale value",
        )
    }

    // updateFromStorage is a one-shot cold-start self-heal with the same check-then-apply race but no
    // later emission to recover, so it re-checks the guard after publishing and re-applies the write.
    @Test
    fun updateFromStorage_racingUserWrite_isNotClobbered() {
        val state = newState("A") // syncedValue = "A"
        // Race a user write of "B" into the window between updateFromStorage's guard check and its publish.
        state.betweenCheckAndPublishForTest = {
            state.betweenCheckAndPublishForTest = null
            state.value = "B"
        }

        state.updateFromStorage("A-persisted")

        assertEquals(
            "B", state.value,
            "a user write racing the one-shot cold-start self-heal must not be clobbered; " +
                "before the fix it stayed stuck on the stale persisted value",
        )
    }

    // A write that nets back to the last synced value leaves the latch down, so the latch cannot stand
    // in for "a write is in flight": the heal must consult the unresolved-write slot instead.
    @Test
    fun updateFromStorage_writeNettingBackToSyncedValue_isNotClobberedAndKeepsItsRollbackSlot() {
        val state = newState("A") // syncedValue = "A"

        state.value = "B"         // arms the latch
        state.value = "A"         // nets back to the synced value: the latch drops, the write is in flight
        val inFlight = state.writeTokenInFlight()

        state.updateFromStorage("hello")

        assertEquals("A", state.value, "the cold-start heal must not publish over a write that is still in flight")
        assertEquals("A", state.lastSyncedValue, "storage never confirmed anything, so the baseline must not move")

        // The slot must still name that write, else its persist failing has no rollback record.
        state.reconcileAfterFailedPersist(inFlight, durableValue = "durable")
        assertEquals("durable", state.value, "the heal must not settle a write it did not observe echo")
    }

    // Control: with nothing in flight the one-shot heal still does its job.
    @Test
    fun updateFromStorage_withNoWriteInFlight_publishesAndRepinsTheBaseline() {
        val state = newState("A")

        state.updateFromStorage("hello")

        assertEquals("hello", state.value)
        assertEquals("hello", state.lastSyncedValue)
    }

    @Test
    fun observeFromStorage_coldStart_takesFirstEmissionAndCompletes() = runTest {
        val state = newState("default")

        state.observeFromStorage(
            flow = flowOf("persisted"),
            coldStart = true,
            observeExternalChanges = false,
        )

        assertEquals("persisted", state.value)
    }

    @Test
    fun observeFromStorage_warmStart_noScope_noOp() = runTest {
        val state = newState("warm_initial")
        var flowCollected = false
        val instrumentedFlow = flow<String> {
            flowCollected = true
            emit("would_propagate")
        }

        state.observeFromStorage(
            flow = instrumentedFlow,
            coldStart = false,
            observeExternalChanges = false,
        )

        assertEquals("warm_initial", state.value)
        assertEquals(false, flowCollected, "warm-start path must not subscribe to flow")
    }

    @Test
    fun observeFromStorage_coldStart_doesNotClobberUserWrite() = runTest {
        val state = newState("default")
        val flow = MutableSharedFlow<String>(replay = 0)

        val job = launch {
            state.observeFromStorage(
                flow = flow,
                coldStart = true,
                observeExternalChanges = false,
            )
        }
        advanceUntilIdle()

        state.value = "user_set"

        // Persisted value finally lands; it must not overwrite the user's value.
        flow.emit("persisted")
        advanceUntilIdle()
        assertEquals("user_set", state.value)

        job.cancel()
    }

    @Test
    fun observeFromStorage_coldStart_timeoutLeavesStateUntouched() = runTest {
        val state = newState("default")
        val neverEmits = flow<String> {
            delay(Long.MAX_VALUE)
        }

        val job = launch {
            state.observeFromStorage(
                flow = neverEmits,
                coldStart = true,
                observeExternalChanges = false,
                selfHealTimeoutMs = 1_000L,
            )
        }
        advanceTimeBy(2_000L)
        advanceUntilIdle()

        assertEquals("default", state.value)
        assertEquals(true, job.isCompleted)
    }
}
