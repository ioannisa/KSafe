@file:OptIn(
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
    kotlinx.coroutines.InternalCoroutinesApi::class,
    kotlinx.coroutines.ExperimentalForInheritanceCoroutinesApi::class,
)

package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: `updateFromFlow` never lets a stale, disk-derived observer emission clobber a value
 * the user just wrote — a user-write guard holds until the write's own echo arrives, then external
 * reflection resumes.
 */
class KSafeStateFlowClobberTest {

    @Test
    fun updateFromFlow_appliesBeforeWrite_thenSkipsAfterUserWrite() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        msf.updateFromFlow("external")
        assertEquals("external", msf.value)

        msf.value = "user"

        // A stale disk echo (older value) must not revert the user's write.
        msf.updateFromFlow("stale_echo")
        assertEquals("user", msf.value, "a stale observer emission must not clobber the user's write")
    }

    @Test
    fun updateFromFlow_isGuarded_afterCompareAndSetWrite() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        msf.compareAndSet("init", "user_cas")
        msf.updateFromFlow("stale_echo")
        assertEquals("user_cas", msf.value, "compareAndSet must arm the guard like a plain set")
    }

    /** The guard is precise, not permanent: once the write's echo arrives, newer external changes reflect again. */
    @Test
    fun updateFromFlow_resumesExternalReflection_afterEchoCatchesUp() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        msf.value = "user"

        msf.updateFromFlow("stale_echo")
        assertEquals("user", msf.value)

        // The user's own write round-trips through disk → the flow has caught up.
        msf.updateFromFlow("user")
        assertEquals("user", msf.value)

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
     * An idempotent write (`value = X` when already X and in sync with storage) must not
     * permanently latch the guard: `distinctUntilChanged` eats the re-write so no echo ever
     * arrives, and a latched guard would suppress every future external change.
     */
    @Test
    fun updateFromFlow_idempotentWrite_doesNotLatchGuard() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        // Sync with storage, then re-write the same value (a common no-op update).
        msf.updateFromFlow("synced")
        msf.value = "synced"

        msf.updateFromFlow("external_new")
        assertEquals(
            "external_new", msf.value,
            "an idempotent write must not permanently suppress external observation",
        )
    }

    /**
     * A write sequence that nets back to the synced value (A→B→A within one coalescing window)
     * produces no distinct echo either, so it must not latch the guard permanently.
     */
    @Test
    fun updateFromFlow_netZeroToggle_doesNotLatchGuard() {
        val msf = KSafeMutableStateFlow(initialValue = "A", persist = { /* no-op */ })
        msf.updateFromFlow("A")

        // A → B → A: distinctUntilChanged emits nothing for the net-unchanged value, so no echo arrives.
        msf.value = "B"
        msf.value = "A"

        msf.updateFromFlow("external_new")
        assertEquals(
            "external_new", msf.value,
            "an A→B→A net-zero write must not permanently suppress external observation",
        )
    }

    /**
     * The user-write guard's check-then-apply in `updateFromFlow` is not atomic against the
     * setter, so a stale emission that read the guard as clear before the setter armed it can
     * clobber the visible value after the setter ran. The source flow is distinctUntilChanged, so
     * the user's value is never re-emitted — the clobber would be permanent. The user-write echo
     * must re-apply the value (self-heal).
     */
    @Test
    fun updateFromFlow_userWriteEcho_selfHealsAStaleClobber() {
        val msf = KSafeMutableStateFlow(initialValue = "A", persist = { /* no-op */ })
        msf.updateFromFlow("A")   // sync baseline
        msf.value = "B"           // arms the guard
        assertEquals("B", msf.value)

        // A stale "A" emission clobbers the visible value after the guard was armed (the raced check-then-apply).
        msf.simulateStaleClobberForTest("A")
        assertEquals("A", msf.value, "precondition: the stale emission diverged the visible state")

        msf.updateFromFlow("B")   // the echo of the user's own write
        assertEquals(
            "B", msf.value,
            "the user-write echo must restore the value a stale emission clobbered; " +
                "before the fix it stayed stuck on the stale value",
        )
    }
}
