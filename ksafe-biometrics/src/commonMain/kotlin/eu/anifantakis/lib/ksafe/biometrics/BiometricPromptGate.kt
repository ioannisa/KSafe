package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Serializes biometric-prompt presentation so at most one prompt is in flight.
 *
 * Android's `BiometricPrompt` shares an activity-scoped `BiometricViewModel`: each new prompt
 * overwrites the previous client callback, and `authenticate()` while a prompt is showing is
 * silently dropped — so concurrent requests would resume only one caller and strand the other.
 * This gate makes callers queue instead. Cancellation of a waiting or holding caller releases
 * the [Mutex], so a cancelled caller can never strand the next one.
 */
internal class BiometricPromptGate {
    private val mutex = Mutex()

    /** Runs [block] (the show-prompt-and-await coroutine) holding the single-prompt lock. */
    suspend fun <T> withSinglePrompt(block: suspend () -> T): T = mutex.withLock { block() }
}
