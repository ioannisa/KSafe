package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.coroutines.coroutineContext
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: [seedBiometricSessionIfActive] skips the seed (and propagates cancellation) when the
 * coroutine is no longer active — a cancelled auth must not grant a later call a prompt-free pass —
 * skips it when the key's revocation epoch moved while the prompt was up — a `clearBiometricAuth()`
 * must not be undone by an in-flight success — and seeds normally otherwise. The commonMain helper
 * backs the Android + JVM + web verify-paths; verified here on JVM.
 */
class SeedBiometricSessionIfActiveTest {

    private fun keyFor(scope: String) = BiometricAuthSession.sessionKey(scope, requireStrict = false)

    @Test
    fun doesNotSeed_whenCoroutineWasCancelled() = runBlocking {
        val key = keyFor("cancelled")
        val epoch = BiometricAuthSession.revocationEpoch(key)
        var seeded = false
        coroutineScope {
            val job = launch {
                // Auth succeeded, but the caller's coroutine was cancelled before the seed runs.
                coroutineContext.job.cancel()
                try {
                    seedBiometricSessionIfActive(key, epoch) { seeded = true }
                } catch (_: CancellationException) {
                    // expected — must propagate
                }
            }
            job.join()
        }
        assertFalse(seeded, "a cancelled auth must NOT seed the session cache (biometric-gate bypass)")
    }

    @Test
    fun seeds_whenCoroutineStillActive() = runBlocking {
        val key = keyFor("active")
        var seeded = false
        seedBiometricSessionIfActive(key, BiometricAuthSession.revocationEpoch(key)) { seeded = true }
        assertTrue(seeded, "an active, successful auth must seed the session cache")
    }

    @Test
    fun doesNotSeed_whenTheKeyWasRevokedMidPrompt() = runBlocking {
        val key = keyFor("revoked-mid-prompt")
        val epochAtPromptStart = BiometricAuthSession.revocationEpoch(key)
        // clearBiometricAuth(scope) ran while the prompt was still on screen.
        BiometricAuthSession.markRevoked(key)
        var seeded = false
        seedBiometricSessionIfActive(key, epochAtPromptStart) { seeded = true }
        assertFalse(seeded, "a success landing after a scoped revocation must NOT re-seed the cache")
    }

    @Test
    fun doesNotSeed_whenAGlobalRevocationHappenedMidPrompt() = runBlocking {
        val key = keyFor("global-revoked-mid-prompt")
        val epochAtPromptStart = BiometricAuthSession.revocationEpoch(key)
        // clearBiometricAuth() (all scopes) ran while the prompt was still on screen.
        BiometricAuthSession.markAllRevoked()
        var seeded = false
        seedBiometricSessionIfActive(key, epochAtPromptStart) { seeded = true }
        assertFalse(seeded, "a success landing after a global revocation must NOT re-seed the cache")
    }

    @Test
    fun seeds_whenOnlyAnUnrelatedKeyWasRevokedMidPrompt() = runBlocking {
        val key = keyFor("undisturbed")
        val epochAtPromptStart = BiometricAuthSession.revocationEpoch(key)
        BiometricAuthSession.markRevoked(keyFor("some-other-scope"))
        var seeded = false
        seedBiometricSessionIfActive(key, epochAtPromptStart) { seeded = true }
        assertTrue(seeded, "revoking an unrelated scope must not block this scope's seed")
    }

    @Test
    fun rollsBack_whenARevocationLandsBetweenTheEpochCheckAndTheSeedWrite() = runBlocking {
        val key = keyFor("revoked-mid-seed")
        val epochAtPromptStart = BiometricAuthSession.revocationEpoch(key)
        var seeded = false
        var rolledBack = false
        seedBiometricSessionIfActive(key, epochAtPromptStart, unseed = { rolledBack = true }) {
            // clearBiometricAuth() lands exactly between the epoch compare and the timestamp
            // write — the narrow window the post-write re-check exists to close.
            BiometricAuthSession.markRevoked(key)
            seeded = true
        }
        assertTrue(seeded, "the seed itself ran before the revocation was observable")
        assertTrue(rolledBack, "a clear racing the seed write must be detected and rolled back")
    }

    @Test
    fun doesNotRollBack_whenNoRevocationRacedTheSeed() = runBlocking {
        val key = keyFor("undisturbed-seed")
        var seeded = false
        var rolledBack = false
        seedBiometricSessionIfActive(
            key, BiometricAuthSession.revocationEpoch(key),
            unseed = { rolledBack = true },
        ) { seeded = true }
        assertTrue(seeded)
        assertFalse(rolledBack, "an un-raced seed must keep its authorization window")
    }
}
