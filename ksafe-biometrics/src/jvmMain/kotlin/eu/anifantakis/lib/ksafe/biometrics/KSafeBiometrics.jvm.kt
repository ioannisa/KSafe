package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext

// JVM biometrics: Touch ID on macOS, Windows Hello on Windows, pass-through elsewhere.
// -Dksafe.biometrics.jvm.prompts=off (or env KSAFE_BIOMETRICS_JVM_PROMPTS=off) restores the
// always-true no-op.

private val directCallbackScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

// Two overlapping OS ceremonies stack dialogs, or the loser fails as DeviceBusy on Windows.
private val promptGate = BiometricPromptGate()

/** Test seam: replaces the OS prompt. */
internal var desktopPromptOverrideForTest: ((reason: String, allowFallback: Boolean) -> Boolean)? = null

/** Test seam: replaces the OS availability probe. */
internal var desktopAvailabilityOverrideForTest: ((allowFallback: Boolean) -> Boolean)? = null

private enum class DesktopOs { MAC, WINDOWS, OTHER }

private val desktopOs: DesktopOs by lazy {
    val name = System.getProperty("os.name").orEmpty().lowercase()
    when {
        name.contains("mac") || name.contains("darwin") -> DesktopOs.MAC
        name.contains("windows") -> DesktopOs.WINDOWS
        else -> DesktopOs.OTHER
    }
}

internal fun desktopPromptsDisabled(): Boolean =
    System.getProperty("ksafe.biometrics.jvm.prompts")?.equals("off", ignoreCase = true) == true ||
        System.getenv("KSAFE_BIOMETRICS_JVM_PROMPTS")?.equals("off", ignoreCase = true) == true

/** The platform prompt, or `null` where no prompt path exists and the pass-through applies. */
private suspend fun runDesktopPrompt(reason: String, allowFallback: Boolean): Boolean? {
    desktopPromptOverrideForTest?.let { return it(reason, allowFallback) }
    if (desktopPromptsDisabled()) return null
    return when (desktopOs) {
        DesktopOs.MAC -> if (MacLocalAuthentication.isAvailable) {
            MacLocalAuthentication.evaluate(reason, allowFallback)
        } else null
        DesktopOs.WINDOWS -> if (WindowsHello.isAvailable) {
            // Off-dispatcher, and interruptible so cancellation reaches the poll loop.
            runInterruptible(Dispatchers.IO) { WindowsHello.evaluate(reason, allowFallback) }
        } else null
        DesktopOs.OTHER -> null
    }
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

    // Re-check inside the gate: a caller we queued behind may have just seeded this scope.
    var skippedAsFreshlyAuthorized = false
    val prompted = promptGate.withSinglePrompt {
        if (attempt.isFresh()) {
            skippedAsFreshlyAuthorized = true
            null
        } else {
            val outcome = runDesktopPrompt(reason, allowDeviceCredentialFallback)
            // Seed while the gate is still HELD, or a queued caller re-checks freshness against
            // a cache we have not written. seedIfActive drops a success whose scope was revoked.
            if (outcome ?: true) attempt.seedIfActive()
            outcome
        }
    }
    if (skippedAsFreshlyAuthorized) return true

    return prompted ?: true // legacy pass-through where no prompt path exists
}

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    title: String?,
    cancelLabel: String?,
    onResult: (Boolean) -> Unit,
) {
    // No main thread to converge on: the callback runs on a background dispatcher thread.
    directCallbackScope.deliverBiometricResult(onResult) {
        platformVerifyBiometric(reason, authorizationDuration, allowDeviceCredentialFallback, title, cancelLabel)
    }
}

internal actual suspend fun platformBiometricsAvailable(allowDeviceCredentialFallback: Boolean): Boolean {
    desktopAvailabilityOverrideForTest?.let { return it(allowDeviceCredentialFallback) }
    if (desktopPromptsDisabled()) return false
    return when (desktopOs) {
        DesktopOs.MAC -> MacLocalAuthentication.isAvailable &&
            MacLocalAuthentication.canEvaluate(allowDeviceCredentialFallback)
        // Blocking COM round-trip: keep it off the caller's dispatcher.
        DesktopOs.WINDOWS -> WindowsHello.isAvailable &&
            withContext(Dispatchers.IO) { WindowsHello.checkAvailability() }
        DesktopOs.OTHER -> false
    }
}

internal actual fun platformBiometricsAvailableDirect(
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
) {
    directCallbackScope.deliverBiometricResult(onResult) {
        platformBiometricsAvailable(allowDeviceCredentialFallback)
    }
}
