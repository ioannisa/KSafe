package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Serializes biometric-prompt presentation so at most one prompt is in flight.
 * Android's `BiometricPrompt` shares an activity-scoped view model, so a second
 * `authenticate()` while one is showing is silently dropped and would strand a
 * caller; queued callers wait instead. Cancelling a waiting/holding caller
 * releases the [Mutex], so it never strands the next one.
 */
internal class BiometricPromptGate {
    private val mutex = Mutex()

    /** Runs [block] holding the single-prompt lock. */
    suspend fun <T> withSinglePrompt(block: suspend () -> T): T = mutex.withLock { block() }
}
