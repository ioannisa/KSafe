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
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: observeFromStorage's live/cold-start/warm-start lifecycle — external emissions reflect, the user-write guard suppresses stale echoes yet self-heals, and cold-start honors its timeout.
 */
class ObserveFromStorageTest {

    private fun newState(initial: String = "initial"): KSafeComposeState<String> =
        KSafeComposeState(
            initialValue = initial,
            valueSaver = { },
            policy = structuralEqualityPolicy(),
        )

    // Live mode: emissions reflect until the user writes, then stale disk echoes are suppressed.
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

        // After a user write, a stale disk echo must not revert it.
        state.value = "user_wrote"
        flow.emit("stale_echo")
        advanceUntilIdle()
        assertEquals("user_wrote", state.value, "a stale flow emission must not clobber the user's write")

        job.cancel()
    }

    // The write guard is precise, not permanent: once the write's echo arrives, newer external changes reflect again.
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

        // Stale pre-write echo: suppressed.
        flow.emit("stale_echo")
        advanceUntilIdle()
        assertEquals("user_wrote", state.value)

        // The user's own write round-trips through disk, so the flow catches up.
        flow.emit("user_wrote")
        advanceUntilIdle()
        assertEquals("user_wrote", state.value)

        // A genuinely newer external write must now reflect again.
        flow.emit("external_new")
        advanceUntilIdle()
        assertEquals(
            "external_new", state.value,
            "after the write's echo, newer external changes must reflect again",
        )

        // A fresh user write re-arms the guard until its own echo.
        state.value = "user_2"
        flow.emit("external_new")
        advanceUntilIdle()
        assertEquals("user_2", state.value, "a re-armed guard must suppress stale echoes again")

        job.cancel()
    }

    // updateFromFlow's guard check-then-apply isn't atomic against the setter, so a stale emission can clobber a write.
    // The user-write echo re-applies the value (self-heal), since distinctUntilChanged means no other emission would.
    @Test
    fun updateFromFlow_userWriteEcho_selfHealsAStaleClobber() {
        val state = newState("A")            // syncedValue = "A"
        state.value = "B"                     // arms the guard; _internalState = "B", lastUserWrite = "B"
        assertEquals("B", state.value)

        // Reproduce the raced outcome: a stale "A" emission clobbers the visible value after the guard was armed.
        state.simulateStaleClobberForTest("A")
        assertEquals("A", state.value, "precondition: the stale emission diverged the visible state")

        // The echo of the user's own write arrives.
        state.updateFromFlow("B")

        assertEquals(
            "B", state.value,
            "the user-write echo must restore the value a stale emission clobbered; " +
                "before the fix it stayed stuck on the stale value",
        )
    }

    // updateFromStorage is a one-shot cold-start self-heal with the same check-then-apply race but no later emission
    // to recover. A user write racing between its guard check and publish must not be clobbered: it re-checks the
    // guard after publishing and re-applies the user's value.
    @Test
    fun updateFromStorage_racingUserWrite_isNotClobbered() {
        val state = newState("A") // syncedValue = "A"
        // Race a user write of "B" into the window between updateFromStorage's guard check and its publish.
        state.betweenCheckAndPublishForTest = {
            state.betweenCheckAndPublishForTest = null
            state.value = "B"
        }

        // The cold-start heal delivers the stale persisted value.
        state.updateFromStorage("A-persisted")

        assertEquals(
            "B", state.value,
            "a user write racing the one-shot cold-start self-heal must not be clobbered; " +
                "before the fix it stayed stuck on the stale persisted value",
        )
    }

    // Cold-start one-shot: observeExternalChanges=false + coldStart=true takes the first emission via updateFromStorage.
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

    // Warm-start no-op: observeExternalChanges=false + coldStart=false subscribes to nothing and mutates nothing.
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

    // Cold-start self-heal must not clobber a value written between launch and the flow's first emission (gated by the user-write guard).
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

        // User writes before the persisted value arrives.
        state.value = "user_set"

        // Persisted value finally lands; it must not overwrite the user's value.
        flow.emit("persisted")
        advanceUntilIdle()
        assertEquals("user_set", state.value)

        job.cancel()
    }

    // Cold-start self-heal honors selfHealTimeoutMs: if the flow never emits, state stays initial and the helper returns.
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
