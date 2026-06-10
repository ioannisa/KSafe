package eu.anifantakis.lib.ksafe.biometrics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Pins the shared biometric-cache decisions: [BiometricAuthSession.shouldCache]
 * must treat `duration <= 0` (the documented opt-out) as non-caching, and
 * [BiometricAuthSession.sessionKey] must keep the global (null) scope distinct
 * from every caller-supplied scope, including the empty string.
 */
class BiometricAuthSessionTest {

    // ---- shouldCache ----

    @Test
    fun shouldCache_isFalse_forNullDuration() {
        assertFalse(BiometricAuthSession.shouldCache(null))
    }

    @Test
    fun shouldCache_isFalse_forZeroDuration() {
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

    // ---- sessionKey ----

    @Test
    fun sessionKey_null_differsFrom_emptyString() {
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
