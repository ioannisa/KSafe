package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Keeps one prompt in flight at a time: Android's `BiometricPrompt` silently drops a second
 * `authenticate()` while one is showing, stranding that caller.
 */
internal class BiometricPromptGate {
    private val mutex = Mutex()

    suspend fun <T> withSinglePrompt(block: suspend () -> T): T = mutex.withLock { block() }
}

/**
 * Prompt text a platform can use, or null for its own default; blank counts as absent. Android's
 * `PromptInfo` rejects an empty title, and that throw reaches the caller as a plain `false`.
 */
internal fun promptTextOrNull(value: String?): String? = value?.takeIf { it.isNotBlank() }

/** A blank reason makes Apple's `evaluatePolicy` raise, so fall back to the built-in default. */
internal fun promptReason(reason: String): String = reason.ifBlank { DEFAULT_BIOMETRIC_REASON }

internal const val DEFAULT_BIOMETRIC_REASON: String = "Authenticate to continue"
