@file:OptIn(
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
    kotlinx.coroutines.InternalCoroutinesApi::class,
    kotlinx.coroutines.ExperimentalForInheritanceCoroutinesApi::class,
)

package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: `updateFromFlow` never lets the stale pre-write disk snapshot clobber a value the user
 * just wrote, yet stays live — any other emission (the write's echo OR a genuine external change)
 * is reflected and clears the guard, so an echo lost to a failed/conflated persist can't leave the
 * flow permanently deaf. In the real `distinctUntilChanged` flow the only value that can momentarily
 * revert an optimistic write is the pre-write snapshot ([syncedValue]), so the tests feed that.
 * Also locks in `reconcileAfterFailedPersist`: a failed fire-and-forget persist reverts the
 * optimistic value to the durable one unless a newer write owns the state.
 */
class KSafeStateFlowClobberTest {

    @Test
    fun updateFromFlow_appliesBeforeWrite_thenSkipsAfterUserWrite() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        msf.updateFromFlow("external")
        assertEquals("external", msf.value)

        msf.value = "user"

        // The pre-write snapshot ("external") is the value a lagging disk read would carry; it must
        // not revert the user's write.
        msf.updateFromFlow("external")
        assertEquals("user", msf.value, "a stale observer emission must not clobber the user's write")
    }

    @Test
    fun updateFromFlow_isGuarded_afterCompareAndSetWrite() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        msf.compareAndSet("init", "user_cas")
        // "init" is the pre-CAS synced value — the one stale snapshot the guard suppresses.
        msf.updateFromFlow("init")
        assertEquals("user_cas", msf.value, "compareAndSet must arm the guard like a plain set")
    }

    /** The guard is precise, not permanent: once the write's echo arrives, newer external changes reflect again. */
    @Test
    fun updateFromFlow_resumesExternalReflection_afterEchoCatchesUp() {
        val msf = KSafeMutableStateFlow(initialValue = "init", persist = { /* no-op */ })

        msf.value = "user"

        // "init" is the pre-write synced value — suppressed while the write propagates.
        msf.updateFromFlow("init")
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

    /**
     * Liveness: if the write's echo never arrives (failed or conflated persist), the guard must not
     * latch forever. The stale pre-write snapshot is still suppressed, but a later genuine external
     * change must reflect — before the fix, only an exact `lastUserWrite` match cleared the guard, so
     * a lost echo left the flow permanently deaf to external updates for that key.
     */
    @Test
    fun updateFromFlow_lostEcho_stillReflectsExternalChange() {
        val msf = KSafeMutableStateFlow(initialValue = "A", persist = { /* echo never arrives */ })
        msf.updateFromFlow("A")   // sync baseline: syncedValue = A
        msf.value = "B"           // arms the guard; the "B" echo will never come
        assertEquals("B", msf.value)

        msf.updateFromFlow("A")   // the stale pre-write snapshot: still suppressed
        assertEquals("B", msf.value, "the pre-write value must not revert the user's write")

        msf.updateFromFlow("external") // a genuine external change while the echo is lost
        assertEquals(
            "external", msf.value,
            "a lost echo must not leave the StateFlow permanently deaf to external updates",
        )
    }

    /**
     * A fire-and-forget persist that fails leaves the flow showing a value that never became
     * durable: storage never changed, so no echo arrives, and the durable value can't correct
     * it — its re-emission is either impossible (distinctUntilChanged) or suppressed as the
     * pre-write snapshot. The failure callback's reconcile must revert to the durable value
     * and release the latch.
     */
    @Test
    fun reconcileAfterFailedPersist_revertsThePhantom_toTheDurableValue() {
        val msf = KSafeMutableStateFlow(initialValue = "A", persist = { /* fails downstream */ })
        msf.updateFromFlow("A")   // sync baseline
        msf.value = "B"           // optimistic write whose persist fails
        assertEquals("B", msf.value)

        msf.reconcileAfterFailedPersist(failedValue = "B", durableValue = "A")

        assertEquals("A", msf.value, "a failed persist must revert the flow to the durable value")
        msf.updateFromFlow("external")
        assertEquals("external", msf.value, "external changes must keep reflecting after the reconcile")
    }

    /** A newer user write owns the state; a stale failure of an older write must not clobber it. */
    @Test
    fun reconcileAfterFailedPersist_isANoOp_whenANewerWriteOwnsTheState() {
        val msf = KSafeMutableStateFlow(initialValue = "A", persist = { /* no-op */ })
        msf.updateFromFlow("A")
        msf.value = "B"
        msf.value = "C" // supersedes B before B's failure lands

        msf.reconcileAfterFailedPersist(failedValue = "B", durableValue = "A")

        assertEquals("C", msf.value, "an older write's failure must not revert a newer in-flight write")
    }
}
