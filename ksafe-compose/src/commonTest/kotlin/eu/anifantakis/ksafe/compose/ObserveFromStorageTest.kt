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
 * Unit tests for [KSafeComposeState.observeFromStorage].
 *
 * The helper is the single source of truth for the persistent-state
 * observation lifecycle used by both [eu.anifantakis.lib.ksafe.compose.mutableStateOf]
 * (property-delegate path) and `rememberKSafeState` (composition-scoped path).
 * Testing it in isolation — outside any composition — verifies the behavior
 * contract both call sites depend on.
 */
class ObserveFromStorageTest {

    private fun newState(initial: String = "initial"): KSafeComposeState<String> =
        KSafeComposeState(
            initialValue = initial,
            valueSaver = { /* no-op */ },
            policy = structuralEqualityPolicy(),
        )

    /**
     * Live mode (`observeExternalChanges = true`): flow emissions propagate
     * into the state until the user writes, after which stale disk echoes are
     * suppressed so they can't clobber the in-flight write.
     */
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

        // Before any local write, external emissions reflect.
        flow.emit("first")
        advanceUntilIdle()
        assertEquals("first", state.value)

        flow.emit("second")
        advanceUntilIdle()
        assertEquals("second", state.value)

        // After the user writes, a stale/older disk echo must NOT revert the
        // write (the disk-derived flow lags optimistic writes).
        state.value = "user_wrote"
        flow.emit("stale_echo")
        advanceUntilIdle()
        assertEquals("user_wrote", state.value, "a stale flow emission must not clobber the user's write")

        job.cancel()
    }

    /**
     * The user-write guard must be precise, not permanent: once the observed
     * flow catches up with the user's own write (the echo arrives), genuinely
     * newer external changes must reflect again, as the `scope` /
     * `observeExternalChanges` KDocs promise.
     */
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

        // The user's own write round-trips through disk → the flow caught up.
        flow.emit("user_wrote")
        advanceUntilIdle()
        assertEquals("user_wrote", state.value)

        // A genuinely newer external write (another screen / background sync)
        // must now reflect again.
        flow.emit("external_new")
        advanceUntilIdle()
        assertEquals(
            "external_new", state.value,
            "after the write's echo, newer external changes must reflect again",
        )

        // And a fresh user write re-arms the guard until its own echo.
        state.value = "user_2"
        flow.emit("external_new") // late re-emission, stale vs user_2
        advanceUntilIdle()
        assertEquals("user_2", state.value, "a re-armed guard must suppress stale echoes again")

        job.cancel()
    }

    /**
     * FEEDBACK_4 M-F: the user-write guard's check-then-apply in `updateFromFlow` is
     * not atomic against the setter, so a stale flow emission that read the guard as
     * clear before the setter armed it can clobber the visible value to the pre-write
     * value AFTER the setter ran. Because the observed flow is `distinctUntilChanged`,
     * the user's value is never re-emitted — the clobber used to be PERMANENT. The
     * user-write echo must now re-apply the value (self-heal), turning a permanent loss
     * into (at worst) the already-accepted transient flicker.
     */
    @Test
    fun updateFromFlow_userWriteEcho_selfHealsAStaleClobber() {
        val state = newState("A")            // syncedValue = "A"
        state.value = "B"                     // arms the guard; _internalState = "B", lastUserWrite = "B"
        assertEquals("B", state.value)

        // Reproduce the raced outcome: a stale "A" emission clobbered the visible value
        // AFTER the guard was armed (the non-atomic check-then-apply the fix addresses).
        state.simulateStaleClobberForTest("A")
        assertEquals("A", state.value, "precondition: the stale emission diverged the visible state")

        // The echo of the user's own write arrives.
        state.updateFromFlow("B")

        assertEquals(
            "B", state.value,
            "the user-write echo must restore the value a stale emission clobbered (M-F); " +
                "before the fix it stayed stuck on the stale value",
        )
    }

    /**
     * FEEDBACK_4 H7: the one-shot cold-start self-heal (`updateFromStorage`) has the same
     * check-then-apply race as `updateFromFlow`, but — being one-shot — has NO later emission
     * to self-heal, so a clobber used to be PERMANENT. A user write racing into the window
     * between the guard check and the publish must not be clobbered by the stale persisted value;
     * `updateFromStorage` now re-checks the guard after its publish and re-applies the user's value.
     */
    @Test
    fun updateFromStorage_racingUserWrite_isNotClobbered() {
        val state = newState("A") // syncedValue = "A"
        // Race a user write of "B" into the window AFTER updateFromStorage's guard check but
        // BEFORE its publish (the non-atomic window). The setter arms the guard + publishes "B".
        state.betweenCheckAndPublishForTest = {
            state.betweenCheckAndPublishForTest = null
            state.value = "B"
        }

        // The cold-start heal delivers the stale persisted value.
        state.updateFromStorage("A-persisted")

        assertEquals(
            "B", state.value,
            "a user write racing the one-shot cold-start self-heal must not be clobbered (H7); " +
                "before the fix it stayed stuck on the stale persisted value",
        )
    }

    /**
     * Cold-start one-shot mode: when `observeExternalChanges = false` and
     * `coldStart = true`, the helper takes the first flow emission and
     * propagates it via `updateFromStorage` (which respects the user-write
     * guard).
     */
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

    /**
     * Warm-start no-op: when `observeExternalChanges = false` and
     * `coldStart = false`, the helper does nothing — no flow subscription,
     * no state mutation. This is the path taken when `mutableStateOf` is
     * declared without a `scope` and the cache was already warm.
     */
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

    /**
     * Cold-start self-heal must not clobber a value the user has written
     * between the helper launching and the flow's first emission. The
     * `updateFromStorage` path is gated by [KSafeComposeState]'s
     * user-write guard (`awaitingWriteEcho`).
     */
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

        // Persisted value finally lands. Must not overwrite the user's value.
        flow.emit("persisted")
        advanceUntilIdle()
        assertEquals("user_set", state.value)

        job.cancel()
    }

    /**
     * Cold-start self-heal honors the `selfHealTimeoutMs` deadline: if the
     * flow does not emit within the timeout, the state stays at its initial
     * value and the helper returns.
     */
    @Test
    fun observeFromStorage_coldStart_timeoutLeavesStateUntouched() = runTest {
        val state = newState("default")
        val neverEmits = flow<String> {
            // Suspend forever — simulates a flow that never delivers.
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
        // Helper should have returned (job completed) once the timeout fired.
        assertEquals(true, job.isCompleted)
    }
}
