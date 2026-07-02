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
 * FEEDBACK_4 low: a biometric prompt can succeed at the very moment the caller's coroutine
 * is cancelled. Seeding the authorization-session cache then would grant a LATER call a
 * prompt-free pass off an authorization the caller never received — a biometric-gate
 * bypass. [seedBiometricSessionIfActive] must skip the seed (and propagate cancellation)
 * when the coroutine is no longer active, and seed normally when it is. (The helper is
 * commonMain and used by the Android + Apple verify-paths; verified here on JVM.)
 */
class SeedBiometricSessionIfActiveTest {

    @Test
    fun doesNotSeed_whenCoroutineWasCancelled() = runBlocking {
        var seeded = false
        coroutineScope {
            val job = launch {
                // Simulate: the auth succeeded, but the caller's coroutine was cancelled
                // before the seed runs.
                coroutineContext.job.cancel()
                try {
                    seedBiometricSessionIfActive { seeded = true }
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
        var seeded = false
        seedBiometricSessionIfActive { seeded = true }
        assertTrue(seeded, "an active, successful auth must seed the session cache")
    }
}
