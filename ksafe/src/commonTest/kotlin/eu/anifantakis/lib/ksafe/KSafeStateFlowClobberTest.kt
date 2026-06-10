@file:OptIn(
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
    kotlinx.coroutines.InternalCoroutinesApi::class,
    kotlinx.coroutines.ExperimentalForInheritanceCoroutinesApi::class,
)

package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Regression test for deep-review #56 (core twin of the Compose #15 fix): the
 * [KSafeMutableStateFlow] backing `asMutableStateFlow` must not let a stale,
 * disk-derived observer-flow emission clobber a value the user just wrote
 * through it. `updateFromFlow` now respects a user-write guard (mirroring the
 * Compose live-observe fix and the core's `updateCache` dirty-key skip).
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
}
