package eu.anifantakis.lib.ksafe.biometrics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Locks in: shouldCache treats `duration <= 0` as non-caching, sessionKey keeps the global (null)
 * scope, every caller scope, and the strict/permissive strengths in distinct, non-forgeable slots,
 * and the revocation epochs give clearBiometricAuth() per-scope and global stamps that in-flight
 * prompts can be checked against at seed time.
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

    // ---- revocation epochs (the seed-time guard against clear-during-prompt) ----
    // Epoch state is process-global and only ever grows, so these assert relative
    // changes from captured values, never absolute ones.

    @Test
    fun markRevoked_changesTheRevokedKeysEpoch_only() {
        val revoked = permissive("epoch-vault")
        val strictSibling = strict("epoch-vault")
        val unrelated = permissive("epoch-other")
        val revokedBefore = BiometricAuthSession.revocationEpoch(revoked)
        val siblingBefore = BiometricAuthSession.revocationEpoch(strictSibling)
        val unrelatedBefore = BiometricAuthSession.revocationEpoch(unrelated)

        BiometricAuthSession.markRevoked(revoked)

        assertNotEquals(
            revokedBefore, BiometricAuthSession.revocationEpoch(revoked),
            "revoking a key must change its epoch, or an in-flight prompt could still re-seed it",
        )
        // Per-scope granularity: each (scope, strength) key is revoked individually.
        assertEquals(siblingBefore, BiometricAuthSession.revocationEpoch(strictSibling))
        assertEquals(unrelatedBefore, BiometricAuthSession.revocationEpoch(unrelated))
    }

    @Test
    fun markAllRevoked_changesEveryKeysEpoch() {
        val scoped = permissive("epoch-global-test")
        val strictScoped = strict("epoch-global-test")
        val globalSlot = permissive(null)
        val scopedBefore = BiometricAuthSession.revocationEpoch(scoped)
        val strictBefore = BiometricAuthSession.revocationEpoch(strictScoped)
        val globalBefore = BiometricAuthSession.revocationEpoch(globalSlot)

        BiometricAuthSession.markAllRevoked()

        assertNotEquals(scopedBefore, BiometricAuthSession.revocationEpoch(scoped))
        assertNotEquals(strictBefore, BiometricAuthSession.revocationEpoch(strictScoped))
        assertNotEquals(globalBefore, BiometricAuthSession.revocationEpoch(globalSlot))
    }

    @Test
    fun revocationEpoch_neverRevisitsACapturedValue() {
        // A global bump after scoped bumps (or any mix) must never bring a key's epoch back
        // to a value an in-flight prompt may have captured — that would undo the revocation.
        val key = permissive("epoch-aba")
        val seen = mutableSetOf(BiometricAuthSession.revocationEpoch(key))
        repeat(3) {
            BiometricAuthSession.markRevoked(key)
            assertTrue(seen.add(BiometricAuthSession.revocationEpoch(key)), "scoped bump must produce a fresh epoch")
        }
        BiometricAuthSession.markAllRevoked()
        assertTrue(seen.add(BiometricAuthSession.revocationEpoch(key)), "global bump must produce a fresh epoch")
        BiometricAuthSession.markRevoked(key)
        assertTrue(seen.add(BiometricAuthSession.revocationEpoch(key)), "scoped bump after a global one must produce a fresh epoch")
    }
}
