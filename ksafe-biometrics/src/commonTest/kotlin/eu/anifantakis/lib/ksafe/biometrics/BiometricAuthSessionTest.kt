package eu.anifantakis.lib.ksafe.biometrics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Locks in: shouldCache treats `duration <= 0` as non-caching, and sessionKey keeps the global (null) scope, every caller scope, and the strict/permissive strengths in distinct, non-forgeable slots.
 */
class BiometricAuthSessionTest {

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

    // Permissive slot allows device-credential; strict is biometrics-only.
    private fun permissive(scope: String?) = BiometricAuthSession.sessionKey(scope, requireStrict = false)
    private fun strict(scope: String?) = BiometricAuthSession.sessionKey(scope, requireStrict = true)

    @Test
    fun sessionKey_null_differsFrom_emptyString() {
        assertNotEquals(permissive(null), permissive(""))
        assertNotEquals(strict(null), strict(""))
    }

    @Test
    fun sessionKey_distinctScopes_dontCollide() {
        assertNotEquals(permissive("a"), permissive("b"))
        assertNotEquals(strict("a"), strict("b"))
    }

    @Test
    fun sessionKey_isStable() {
        assertEquals(permissive(null), permissive(null))
        assertEquals(strict("vault"), strict("vault"))
    }

    @Test
    fun sessionKey_callerCannotForgeGlobalSlot() {
        // Caller scopes are always namespaced, so no caller string can land in the global slot.
        val global = permissive(null)
        assertNotEquals(global, permissive(global))
        assertNotEquals(global, permissive(" ksafe-global-scope"))
    }

    @Test
    fun sessionKey_strictAndPermissive_areDistinct_forSameScope() {
        // A biometrics-only (strict) call must not be served from a cached device-credential (permissive) success.
        assertNotEquals(strict("vault"), permissive("vault"))
        assertNotEquals(strict(null), permissive(null))
    }

    @Test
    fun sessionKey_isInjective_noScopeCanForgeAnotherStrengthSlot() {
        // A caller scope ending in a strictness marker must not collide with another scope's strict/permissive slot.
        assertNotEquals(permissive("a|strict"), strict("a"))
        assertNotEquals(permissive("aS"), strict("a"))
        // The strength discriminator is a prefix, so a scope string that looks like a
        // full key can never land in a different (scope, strength) slot.
        assertNotEquals(strict("vault"), permissive("S ksafe-global-scope"))
        assertNotEquals(strict(null), permissive("Sscope: ksafe-global-scope"))
    }
}
