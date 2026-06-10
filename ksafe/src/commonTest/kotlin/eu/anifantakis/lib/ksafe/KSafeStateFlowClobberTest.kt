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
            "after the write's echo, newer external changes must reflect again (R19)",
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
}
