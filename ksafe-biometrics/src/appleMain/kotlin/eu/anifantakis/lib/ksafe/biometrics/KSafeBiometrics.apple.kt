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

// Apple biometrics: iOS Face ID / Touch ID, macOS device-owner auth. Verify is a pass-through
// that returns true on the Simulator, where no real prompt can be shown.

@OptIn(ExperimentalForeignApi::class)
private fun isSimulator(): Boolean =
    NSProcessInfo.processInfo.environment["SIMULATOR_UDID"] != null

/** Serializes prompts so a caller queued behind an authorization can skip a redundant ceremony. */
private val promptGate = BiometricPromptGate()

// macOS defaults to device-owner auth (many Macs lack Touch ID); iOS is biometrics-only.
// The prompt and the availability probe must ask about the SAME policy.
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

    return promptGate.withSinglePrompt {
        // Re-check inside the gate: the caller we queued behind may have just authorized this
        // scope. A skip authorizes but does not re-seed, so the window cannot extend.
        if (attempt.isFresh()) return@withSinglePrompt true

        suspendCancellableCoroutine { continuation ->
            // Own the LAContext so a cancelled coroutine can invalidate() the pending prompt.
            val context = platform.LocalAuthentication.LAContext()
            continuation.invokeOnCancellation { runCatching { context.invalidate() } }
            CoroutineScope(Dispatchers.Main).launch {
                runLAContextEvaluate(context, reason, allowDeviceCredentialFallback, cancelLabel) { success ->
                    // Do not seed if the caller cancelled, or clearBiometricAuth() revoked the
                    // scope while the prompt was up.
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
}

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    title: String?,
    cancelLabel: String?,
    onResult: (Boolean) -> Unit,
) {
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
    // A null cancelLabel keeps the system's localized one. LAContext has no prompt title, so
    // `title` has no Apple counterpart.
    if (cancelLabel != null) context.localizedCancelTitle = cancelLabel
    // An empty localizedReason raises through interop and kills the process.
    val safeReason = promptReason(reason)
    context.evaluatePolicy(laPolicy(allowDeviceCredentialFallback), localizedReason = safeReason) { success, _ ->
        CoroutineScope(Dispatchers.Main).launch { onResult(success) }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun appleBiometricsAvailability(allowDeviceCredentialFallback: Boolean): Boolean {
    // Simulator verify is a pass-through, so report false: the contract is "will a real prompt show".
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
