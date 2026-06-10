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
     * Live mode (`observeExternalChanges = true`): every flow emission is
     * propagated into the state via `updateFromFlow`, even after the user
     * has NOT yet written — but stops once the user writes, so a stale disk echo
     * can't clobber an in-flight write (deep-review #15).
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

        // After the user writes, a stale/older disk echo must NOT revert the write
        // (the disk-derived flow lags optimistic writes). Pre-fix this clobbered
        // "user_wrote" back to "stale_echo".
        state.value = "user_wrote"
        flow.emit("stale_echo")
        advanceUntilIdle()
        assertEquals("user_wrote", state.value, "a stale flow emission must not clobber the user's write")

        job.cancel()
    }

    /**
     * Review R45: the user-write guard must be precise, not permanent. Once the
     * observed flow catches up with the user's own write (the echo arrives —
     * the write committed and round-tripped through disk), genuinely newer
     * external changes must reflect again, as the `scope` /
     * `observeExternalChanges` KDocs promise. The old one-way latch silently
     * disabled external reflection forever after the first local write.
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
            "after the write's echo, newer external changes must reflect again (R45)",
        )

        // And a fresh user write re-arms the guard until its own echo.
        state.value = "user_2"
        flow.emit("external_new") // late re-emission, stale vs user_2
        advanceUntilIdle()
        assertEquals("user_2", state.value, "a re-armed guard must suppress stale echoes again")

        job.cancel()
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
