package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * JVM implementation of [KSafeBiometrics] — real desktop prompts since 2.1.4:
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
 * `KSAFE_BIOMETRICS_JVM_PROMPTS=off`) restores the pre-2.1.4 always-`true` no-op —
 * the migration path for desktop apps that relied on the old pass-through.
 */

private val biometricAuthSessions = ConcurrentHashMap<String, Long>()

// Monotonic TTL clock (System.nanoTime never goes backward): a wall-clock jump must
// not extend a cached authorization. Mirrors the Apple/Android implementations.
private fun monotonicNowMs(): Long = System.nanoTime() / 1_000_000

private val directCallbackScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

/** Test seam: replaces the OS prompt so unit tests never show real dialogs. */
internal var desktopPromptOverrideForTest: ((reason: String, allowFallback: Boolean) -> Boolean)? = null

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
            // Blocking COM + poll loop — keep it off the caller's dispatcher.
            withContext(Dispatchers.IO) { WindowsHello.evaluate(reason, allowFallback) }
        } else null
        DesktopOs.OTHER -> null
    }
}

internal actual suspend fun platformVerifyBiometric(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
): Boolean {
    if (BiometricAuthSession.shouldCache(authorizationDuration)) {
        val scope = BiometricAuthSession.sessionKey(authorizationDuration!!.scope, requireStrict = !allowDeviceCredentialFallback)
        val lastAuth = biometricAuthSessions[scope] ?: 0L
        val now = monotonicNowMs()
        if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
            return true
        }
    }

    val prompted = runDesktopPrompt(reason, allowDeviceCredentialFallback)
    val success = prompted ?: true // legacy pass-through where no prompt path exists

    if (success && BiometricAuthSession.shouldCache(authorizationDuration)) {
        // Seed only while the caller is still active: a success arriving for a cancelled
        // caller must not grant a later call a prompt-free pass (mirrors appleMain).
        seedBiometricSessionIfActive {
            biometricAuthSessions[
                BiometricAuthSession.sessionKey(authorizationDuration!!.scope, requireStrict = !allowDeviceCredentialFallback)
            ] = monotonicNowMs()
        }
    }
    return success
}

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
) {
    // The JVM has no main thread to converge on (unlike Android/Apple): the callback
    // is delivered on a background dispatcher thread.
    directCallbackScope.launch {
        val result = runCatching {
            platformVerifyBiometric(reason, authorizationDuration, allowDeviceCredentialFallback)
        }.getOrDefault(false)
        onResult(result)
    }
}

internal actual fun platformClearBiometricAuth(scope: String?) {
    if (scope == null) {
        biometricAuthSessions.clear()
        return
    }
    // Clear BOTH the permissive and strict slots for this scope (see BiometricAuthSession).
    biometricAuthSessions.remove(BiometricAuthSession.sessionKey(scope, requireStrict = false))
    biometricAuthSessions.remove(BiometricAuthSession.sessionKey(scope, requireStrict = true))
}
