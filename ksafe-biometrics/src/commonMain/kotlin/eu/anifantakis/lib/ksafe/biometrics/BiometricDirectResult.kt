package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * Shared body of the `*Direct` callback wrappers on platforms whose callback has no main thread
 * to converge on: run the suspending twin in this scope, hand its result to [onResult]. A failure
 * is delivered as `false` — a callback API has nowhere to throw.
 *
 * The scope stays per-platform: it owns the dispatcher and the cancellation semantics, and a
 * detached scope created here would give neither.
 */
internal fun CoroutineScope.deliverBiometricResult(
    onResult: (Boolean) -> Unit,
    compute: suspend () -> Boolean,
) {
    launch {
        val result = runCatching { compute() }.getOrDefault(false)
        onResult(result)
    }
}
