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

/**
 * Prompt text a platform can actually use, or null to fall back to its own default.
 *
 * Blank counts as absent. `null` already means "I have no text, choose for me", and a caller
 * whose string resource or config field resolved to `""` means the same thing without knowing
 * to send null — but Android's `PromptInfo` rejects an empty title, and that throw reaches the
 * caller as a plain `false`, so every authentication would deny with nothing to debug.
 *
 * Applied at both doors into a prompt: [KSafeBiometrics.verifyBiometric], which every platform
 * dispatches through, and Android's own public `BiometricHelper.authenticate`, which an app can
 * call directly. Applying it only at the common one left Apple setting a blank
 * `localizedCancelTitle` and the web naming a passkey `""`.
 */
internal fun promptTextOrNull(value: String?): String? = value?.takeIf { it.isNotBlank() }

/**
 * A blank reason kills the process on Apple (`evaluatePolicy` raises), so it falls back to the
 * built-in default, never to the public [KSafeBiometrics.defaultReason] that may itself be blank.
 */
internal fun promptReason(reason: String): String = reason.ifBlank { DEFAULT_BIOMETRIC_REASON }

internal const val DEFAULT_BIOMETRIC_REASON: String = "Authenticate to continue"
