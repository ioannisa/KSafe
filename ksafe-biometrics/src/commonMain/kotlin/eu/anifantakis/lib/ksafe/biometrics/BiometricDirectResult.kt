package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/** Runs the suspending twin in this scope, reporting a failure as `false` — a callback API has
 *  nowhere to throw. The scope stays per-platform: it owns dispatcher and cancellation. */
internal fun CoroutineScope.deliverBiometricResult(
    onResult: (Boolean) -> Unit,
    compute: suspend () -> Boolean,
) {
    launch {
        val result = runCatching { compute() }.getOrDefault(false)
        onResult(result)
    }
}
