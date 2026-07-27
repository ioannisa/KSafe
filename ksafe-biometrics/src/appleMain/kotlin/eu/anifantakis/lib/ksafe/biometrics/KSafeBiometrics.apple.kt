package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.Foundation.NSProcessInfo
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.OsFamily
import kotlin.native.Platform

/**
 * Apple-platform [KSafeBiometrics] helpers.
 *
 * iOS: Face ID / Touch ID via `LAPolicyDeviceOwnerAuthenticationWithBiometrics`; returns `true` on the Simulator.
 * macOS: `LAPolicyDeviceOwnerAuthentication` — Touch ID, password, or Apple Watch unlock.
 */

@OptIn(ExperimentalForeignApi::class)
private fun isSimulator(): Boolean =
    NSProcessInfo.processInfo.environment["SIMULATOR_UDID"] != null

// macOS defaults to DeviceOwnerAuthentication (many Macs lack Touch ID); iOS is biometrics-only.
// Fallback is opt-in. The prompt and the availability probe must ask about the SAME policy.
private fun laPolicy(allowDeviceCredentialFallback: Boolean) =
    if (allowDeviceCredentialFallback) {
        platform.LocalAuthentication.LAPolicyDeviceOwnerAuthentication
    } else {
        platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics
    }

internal actual suspend fun platformVerifyBiometric(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    title: String?,
    cancelLabel: String?,
): Boolean {
    val attempt = beginBiometricAttempt(authorizationDuration, allowDeviceCredentialFallback)
        ?: return true

    if (isSimulator()) {
        attempt.seedIfActive()
        return true
    }

    return suspendCancellableCoroutine { continuation ->
        // Own the LAContext so a cancelled coroutine can invalidate() the pending prompt; guard resume against a late/repeat callback.
        val context = platform.LocalAuthentication.LAContext()
        continuation.invokeOnCancellation { runCatching { context.invalidate() } }
        CoroutineScope(Dispatchers.Main).launch {
            runLAContextEvaluate(context, reason, allowDeviceCredentialFallback, cancelLabel) { success ->
                // A success arriving after the caller cancelled — or after clearBiometricAuth()
                // revoked the scope while the prompt was up — must NOT seed the cache. Not
                // attempt.seedIfActive(): this callback is not the caller's coroutine, so the
                // liveness check is the continuation's, and the epoch compare is explicit.
                val cacheKey = attempt.cacheKey
                if (success && cacheKey != null && continuation.isActive &&
                    BiometricAuthSession.revocationEpoch(cacheKey) == attempt.epochAtPromptStart
                ) {
                    BiometricSessionStore.seedThenRecheckRevocation(cacheKey, attempt.epochAtPromptStart)
                }
                if (continuation.isActive) continuation.resumeWith(Result.success(success))
            }
        }
    }
}

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    title: String?,
    cancelLabel: String?,
    onResult: (Boolean) -> Unit,
) {
    // Main, like every Apple callback here: the suspending twin owns the cache and prompt logic.
    CoroutineScope(Dispatchers.Main).launch {
        onResult(
            platformVerifyBiometric(
                reason, authorizationDuration, allowDeviceCredentialFallback, title, cancelLabel,
            )
        )
    }
}

@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
private fun runLAContextEvaluate(
    context: platform.LocalAuthentication.LAContext,
    reason: String,
    allowDeviceCredentialFallback: Boolean,
    cancelLabel: String?,
    onResult: (Boolean) -> Unit,
) {
    // Left unset when null so the system supplies its own LOCALIZED cancel title; overriding
    // with a fixed string would ship one language to every locale. LAContext has no title/
    // subtitle — only the reason — so `title` has no Apple counterpart and is ignored.
    if (cancelLabel != null) context.localizedCancelTitle = cancelLabel
    context.evaluatePolicy(laPolicy(allowDeviceCredentialFallback), localizedReason = reason) { success, _ ->
        CoroutineScope(Dispatchers.Main).launch { onResult(success) }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun appleBiometricsAvailability(allowDeviceCredentialFallback: Boolean): Boolean {
    // Simulator verify is a pass-through, so availability reports false: the contract is "will verify show a REAL prompt".
    if (isSimulator()) return false
    return platform.LocalAuthentication.LAContext()
        .canEvaluatePolicy(laPolicy(allowDeviceCredentialFallback), error = null)
}

internal actual suspend fun platformBiometricsAvailable(allowDeviceCredentialFallback: Boolean): Boolean =
    appleBiometricsAvailability(allowDeviceCredentialFallback)

internal actual fun platformBiometricsAvailableDirect(
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
) {
    val result = appleBiometricsAvailability(allowDeviceCredentialFallback)
    CoroutineScope(Dispatchers.Main).launch { onResult(result) }
}
