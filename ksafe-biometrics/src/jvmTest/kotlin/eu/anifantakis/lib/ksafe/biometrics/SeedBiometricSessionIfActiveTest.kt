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
 * and seeds normally when active. The commonMain helper backs the Android + Apple verify-paths; verified here on JVM.
 */
class SeedBiometricSessionIfActiveTest {

    @Test
    fun doesNotSeed_whenCoroutineWasCancelled() = runBlocking {
        var seeded = false
        coroutineScope {
            val job = launch {
                // Auth succeeded, but the caller's coroutine was cancelled before the seed runs.
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
