package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/** Shared body of the platform `*Direct` callback wrappers: runs the suspending variant in this
 *  scope and hands the result to [onResult], with any failure reported as `false`, since a
 *  callback has nowhere to throw. The scope is per-platform; it owns dispatcher and cancellation. */
internal fun CoroutineScope.deliverBiometricResult(
    onResult: (Boolean) -> Unit,
    compute: suspend () -> Boolean,
) {
    launch {
        val result = runCatching { compute() }.getOrDefault(false)
        onResult(result)
    }
}
