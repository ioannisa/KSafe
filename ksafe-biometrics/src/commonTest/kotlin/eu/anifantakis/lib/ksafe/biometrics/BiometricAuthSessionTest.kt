package eu.anifantakis.lib.ksafe.biometrics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Pins the two shared biometric-cache decisions that previously diverged across
 * the Android and Apple actuals.
 *
 * #40 — [BiometricAuthSession.shouldCache]: a duration <= 0 (the documented
 * opt-out) must NOT be cached. The old code gated the cache READ on
 * `duration > 0` but the WRITE on only `!= null`, so an opt-out call still
 * seeded the cache and a later longer-window call was granted with no prompt.
 *
 * #61 — [BiometricAuthSession.sessionKey]: a null (global) scope and a caller's
 * empty-string scope must occupy DISTINCT cache slots. The old code mapped both
 * to "", so a global authorization could satisfy an empty-scope call.
 */
class BiometricAuthSessionTest {

    // ---- #40: shouldCache ----

    @Test
    fun shouldCache_isFalse_forNullDuration() {
        assertFalse(BiometricAuthSession.shouldCache(null))
    }

    @Test
    fun shouldCache_isFalse_forZeroDuration() {
        // The exact opt-out value pinned as constructible by BiometricAuthorizationDurationTest.
        assertFalse(BiometricAuthSession.shouldCache(BiometricAuthorizationDuration(0L, "vault")))
    }

    @Test
    fun shouldCache_isFalse_forNegativeDuration() {
        assertFalse(BiometricAuthSession.shouldCache(BiometricAuthorizationDuration(-1000L, "vault")))
    }

    @Test
    fun shouldCache_isTrue_forPositiveDuration() {
        assertTrue(BiometricAuthSession.shouldCache(BiometricAuthorizationDuration(1L, "vault")))
        assertTrue(BiometricAuthSession.shouldCache(BiometricAuthorizationDuration(60_000L, null)))
    }

    // ---- #61: sessionKey ----

    @Test
    fun sessionKey_null_differsFrom_emptyString() {
        // The headline #61 collision: global (null) vs an empty caller scope.
        assertNotEquals(BiometricAuthSession.sessionKey(null), BiometricAuthSession.sessionKey(""))
    }

    @Test
    fun sessionKey_distinctScopes_dontCollide() {
        assertNotEquals(BiometricAuthSession.sessionKey("a"), BiometricAuthSession.sessionKey("b"))
    }

    @Test
    fun sessionKey_isStable() {
        assertEquals(BiometricAuthSession.sessionKey(null), BiometricAuthSession.sessionKey(null))
        assertEquals(BiometricAuthSession.sessionKey("vault"), BiometricAuthSession.sessionKey("vault"))
    }

    @Test
    fun sessionKey_callerCannotForgeGlobalSlot() {
        // No caller-supplied string — even one mimicking the sentinel — may land
        // in the global slot, because caller scopes are always namespaced.
        val global = BiometricAuthSession.sessionKey(null)
        assertNotEquals(global, BiometricAuthSession.sessionKey(global))
        assertNotEquals(global, BiometricAuthSession.sessionKey(" ksafe-global-scope"))
    }
}
