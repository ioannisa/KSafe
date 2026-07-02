@file:OptIn(
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
    kotlinx.coroutines.InternalCoroutinesApi::class,
    kotlinx.coroutines.ExperimentalForInheritanceCoroutinesApi::class,
)

package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The [KSafeMutableStateFlow] backing `asMutableStateFlow` must not let a
 * stale, disk-derived observer-flow emission clobber a value the user just
 * wrote through it: `updateFromFlow` respects a user-write guard until the
 * write's own echo arrives.
 */
class KSafeStateFlowClobberTest {

    @Test
    fun updateFromFlow_appliesBeforeWrite_thenSkipsAfterUserWrite() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        // Before any local write, external/observer emissions reflect.
        msf.updateFromFlow("external")
        assertEquals("external", msf.value)

        // User writes through the StateFlow.
        msf.value = "user"

        // A stale disk echo (older value) must NOT revert the user's write.
        msf.updateFromFlow("stale_echo")
        assertEquals("user", msf.value, "a stale observer emission must not clobber the user's write")
    }

    @Test
    fun updateFromFlow_isGuarded_afterCompareAndSetWrite() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        // compareAndSet is also a user-write path → must arm the guard.
        msf.compareAndSet("init", "user_cas")
        msf.updateFromFlow("stale_echo")
        assertEquals("user_cas", msf.value, "compareAndSet must arm the guard like a plain set")
    }

    /**
     * The guard must be precise, not permanent: once the observer flow catches
     * up with the user's write (the echo arrives), genuinely newer external
     * changes must reflect again, as the public KDoc promises.
     */
    @Test
    fun updateFromFlow_resumesExternalReflection_afterEchoCatchesUp() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        msf.value = "user"

        // Stale pre-write echo: suppressed.
        msf.updateFromFlow("stale_echo")
        assertEquals("user", msf.value)

        // The user's own write round-trips through disk → the flow caught up.
        msf.updateFromFlow("user")
        assertEquals("user", msf.value)

        // A genuinely newer external write must now reflect again.
        msf.updateFromFlow("external_new")
        assertEquals(
            "external_new", msf.value,
            "after the write's echo, newer external changes must reflect again",
        )
    }

    /** A second write re-arms the guard until its own echo arrives. */
    @Test
    fun updateFromFlow_secondWrite_reArmsGuard_untilItsOwnEcho() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        msf.value = "w1"
        msf.updateFromFlow("w1") // echo of w1 → unlatched

        msf.value = "w2" // re-arms
        msf.updateFromFlow("w1") // late re-emission of w1: stale vs w2 → suppressed
        assertEquals("w2", msf.value, "a stale echo of an OLDER write must not revert the newer write")

        msf.updateFromFlow("w2") // echo of w2 → unlatched
        msf.updateFromFlow("external")
        assertEquals("external", msf.value)
    }

    /**
     * deep-review M2: an idempotent write (`value = X` when already X and in sync
     * with storage) must NOT permanently latch the guard. `distinctUntilChanged`
     * eats the re-write so no echo can ever arrive; if the guard latched, every
     * future external change would be suppressed for the StateFlow's lifetime.
     */
    @Test
    fun updateFromFlow_idempotentWrite_doesNotLatchGuard() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        // Sync with storage, then re-write the SAME value (very common: re-submitting
        // an unchanged form, `flow.value = repo.compute()` returning the same result).
        msf.updateFromFlow("synced")
        msf.value = "synced"

        // External changes must still reflect — the guard must not be stuck.
        msf.updateFromFlow("external_new")
        assertEquals(
            "external_new", msf.value,
            "an idempotent write must not permanently suppress external observation",
        )
    }

    /**
     * deep-review M2: a write sequence that nets back to the synced value
     * (A→B→A within one coalescing window) produces no distinct echo either, so
     * it must not latch the guard permanently.
     */
    @Test
    fun updateFromFlow_netZeroToggle_doesNotLatchGuard() {
        val msf = KSafeMutableStateFlow(initialValue = "A", persist = { /* no-op */ })
        // Establish "A" as the synced baseline.
        msf.updateFromFlow("A")

        // A → B → A: each step changes the value, but the net persisted value is
        // unchanged, so distinctUntilChanged emits nothing and no echo arrives.
        msf.value = "B"
        msf.value = "A"

        msf.updateFromFlow("external_new")
        assertEquals(
            "external_new", msf.value,
            "an A→B→A net-zero write must not permanently suppress external observation",
        )
    }
}
