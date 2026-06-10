package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Serializes biometric-prompt presentation so at most **one** prompt is ever in flight.
 *
 * The Android `BiometricPrompt` is backed by a single activity-scoped `BiometricViewModel`
 * whose client callback is **overwritten** by each new `BiometricPrompt` construction, and a
 * second `authenticate()` while a prompt is already showing is silently dropped. So two
 * concurrent biometric requests (two biometric-gated reads launched in parallel, or a
 * double-tap) would stomp each other's callback: the user sees one prompt, exactly one
 * request is resumed, and the **other suspends forever** (deep-review #14).
 *
 * Routing every prompt through this gate makes concurrent callers **queue**: each shows its
 * prompt only after the previous one has fully resolved. Cancelling a waiting — or holding —
 * caller releases the gate (it's a plain [Mutex]), so a caller whose UI flow times out or is
 * cancelled can never permanently strand the next one.
 */
internal class BiometricPromptGate {
    private val mutex = Mutex()

    /** Runs [block] (the show-prompt-and-await coroutine) holding the single-prompt lock. */
    suspend fun <T> withSinglePrompt(block: suspend () -> T): T = mutex.withLock { block() }
}
