package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext

/**
 * JVM implementation of [KSafeBiometrics] — real desktop prompts since 2.2.0:
 *
 * - **macOS**: Touch ID / password / Apple Watch via `LocalAuthentication` (JNA→ObjC),
 *   with the same policy mapping as the native macOS target.
 * - **Windows**: Windows Hello (biometrics or Hello PIN) via `UserConsentVerifier`
 *   (JNA→WinRT COM interop). Hello treats its PIN as part of Hello, so
 *   `allowDeviceCredentialFallback = false` cannot exclude the PIN here — it still
 *   keys the authorization cache strictly and hard-refuses when Hello is absent.
 * - **Linux / anything else**: the legacy pass-through (`true`) — no portable prompt
 *   API exists there.
 *
 * Escape hatch: `-Dksafe.biometrics.jvm.prompts=off` (or env
 * `KSAFE_BIOMETRICS_JVM_PROMPTS=off`) restores the pre-2.2.0 always-`true` no-op —
 * the migration path for desktop apps that relied on the old pass-through.
 */

private val directCallbackScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

// Serializes desktop prompts like Android and the web: two overlapping OS ceremonies stack
// dialogs (or the loser fails as DeviceBusy on Windows); queued callers re-check the cache
// once the gate is held so a just-authenticated sibling spares them a redundant prompt.
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

/**
 * Runs the platform prompt, or returns `null` when no prompt path exists and the
 * legacy pass-through applies (opt-out, unsupported OS, bridge failed to load).
 */
private suspend fun runDesktopPrompt(reason: String, allowFallback: Boolean): Boolean? {
    desktopPromptOverrideForTest?.let { return it(reason, allowFallback) }
    if (desktopPromptsDisabled()) return null
    return when (desktopOs) {
        DesktopOs.MAC -> if (MacLocalAuthentication.isAvailable) {
            MacLocalAuthentication.evaluate(reason, allowFallback)
        } else null
        DesktopOs.WINDOWS -> if (WindowsHello.isAvailable) {
            // Blocking COM + poll loop — keep it off the caller's dispatcher. Interruptible so
            // coroutine cancellation reaches the poll loop, which cancels the native ceremony.
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

    // Re-check the cache INSIDE the gate: a caller we queued behind may have just seeded this
    // scope, so skip a redundant prompt (skip → authorized, but no re-seed, so the window
    // cannot extend).
    var skippedAsFreshlyAuthorized = false
    val prompted = promptGate.withSinglePrompt {
        if (attempt.isFresh()) {
            skippedAsFreshlyAuthorized = true
            null
        } else {
            val outcome = runDesktopPrompt(reason, allowDeviceCredentialFallback)
            // Seed while the gate is still HELD. A caller queued behind us re-checks freshness
            // the instant the gate changes hands; seeding after the release leaves a window in
            // which it reads a cache we have not written yet and prompts a second time.
            // A success arriving for a cancelled caller — or after clearBiometricAuth() revoked
            // the scope mid-prompt — must not grant a later call a prompt-free pass, which is
            // what seedIfActive checks.
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
    // The JVM has no main thread to converge on: the callback runs on a background dispatcher thread.
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
        // Blocking COM round-trip (prompt-free) — keep it off the caller's dispatcher.
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
