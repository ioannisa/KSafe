package eu.anifantakis.lib.ksafe.biometrics

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in the shared authorization cache every platform now reads and writes: an entry is fresh
 * because it EXISTS (never because its stamp is positive — a monotonic clock's origin is
 * arbitrary), a clear drops both strength slots of the scope it names and nothing else, and a
 * revocation that races the seed write rolls that write back.
 */
class BiometricSessionStoreTest {

    private fun window(scope: String) = BiometricAuthorizationDuration(60_000L, scope)

    private fun keyFor(scope: String, strict: Boolean = false) =
        BiometricAuthSession.sessionKey(scope, requireStrict = strict)

    @Test
    fun seededEntryIsFresh_regardlessOfTheClockOrigin() {
        val key = keyFor("store-seeded")
        BiometricSessionStore.seedThenRecheckRevocation(key, BiometricAuthSession.revocationEpoch(key))
        assertTrue(
            BiometricSessionStore.isFresh(key, window("store-seeded")),
            "a just-seeded entry must be fresh — presence is the sentinel, not the stamp's sign",
        )
    }

    @Test
    fun unseededKeyAndZeroWindowAreNeverFresh() {
        val key = keyFor("store-never-seeded")
        assertFalse(BiometricSessionStore.isFresh(key, window("store-never-seeded")))
        assertFalse(BiometricSessionStore.isFresh(null, window("store-never-seeded")), "no cache key")

        val elapsed = keyFor("store-zero-window")
        BiometricSessionStore.seedThenRecheckRevocation(elapsed, BiometricAuthSession.revocationEpoch(elapsed))
        assertFalse(
            BiometricSessionStore.isFresh(elapsed, BiometricAuthorizationDuration(0L, "store-zero-window")),
            "an elapsed window must not authorize",
        )
    }

    @Test
    fun clearingAScopeDropsBothStrengthSlots_andLeavesOtherScopesAlone() {
        val permissive = keyFor("store-cleared")
        val strict = keyFor("store-cleared", strict = true)
        val other = keyFor("store-untouched")
        listOf(permissive, strict, other).forEach {
            BiometricSessionStore.seedThenRecheckRevocation(it, BiometricAuthSession.revocationEpoch(it))
        }

        BiometricSessionStore.clear("store-cleared")

        assertFalse(BiometricSessionStore.isFresh(permissive, window("store-cleared")))
        assertFalse(BiometricSessionStore.isFresh(strict, window("store-cleared")))
        assertTrue(
            BiometricSessionStore.isFresh(other, window("store-untouched")),
            "clearing one scope must not clear another",
        )
    }

    @Test
    fun clearingEveryScopeDropsEveryEntry() {
        val key = keyFor("store-global-clear")
        BiometricSessionStore.seedThenRecheckRevocation(key, BiometricAuthSession.revocationEpoch(key))

        BiometricSessionStore.clear(null)

        assertFalse(BiometricSessionStore.isFresh(key, window("store-global-clear")))
    }

    @Test
    fun aRevocationRacingTheSeedWriteRollsItBack() {
        val key = keyFor("store-revoked-mid-seed")
        // The epoch the prompt captured before showing UI; clearBiometricAuth() then ran while it
        // was still up, so the success landing now must not leave an authorization behind.
        val staleEpoch = BiometricAuthSession.revocationEpoch(key) - 1

        BiometricSessionStore.seedThenRecheckRevocation(key, staleEpoch)

        assertFalse(BiometricSessionStore.isFresh(key, window("store-revoked-mid-seed")))
    }
}
