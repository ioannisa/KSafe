package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Web (Kotlin/JS + Kotlin/Wasm) implementation of [KSafeBiometrics] — real prompts since
 * 2.2.0 via **WebAuthn platform authenticators** (`navigator.credentials`): Touch ID in
 * Safari/Chrome on macOS, Windows Hello in Edge/Chrome, fingerprint on Android browsers.
 *
 * KSafe uses WebAuthn as a *local re-auth gate* — a self-generated challenge with no
 * server ceremony. The browser enforces user verification before the promise resolves,
 * which is the same guarantee tier as the desktop bridges (an owner-presence UX gate,
 * not a cryptographic proof to a backend).
 *
 * Web-specific behavior:
 * - **First use registers**: the first successful call runs a one-time `create()`
 *   ceremony (which itself verifies the user — it counts as success) and stores the
 *   credential id in `localStorage`; later calls run `get()` against it.
 * - **The [reason] string is NOT displayed** — WebAuthn dialogs are browser-controlled
 *   and accept no custom message (unlike LAContext / BiometricPrompt / Hello).
 * - **User gesture**: browsers may require transient activation — call from a click
 *   handler or the ceremony can be rejected (`NotAllowedError` → `false`).
 * - `allowDeviceCredentialFallback = false` cannot exclude the platform's PIN where the
 *   OS treats it as part of the authenticator (e.g. Windows Hello) — same caveat as the
 *   JVM Windows bridge; it still keys the authorization cache strictly.
 * - When no platform authenticator exists (insecure context, no WebAuthn, no enrolled
 *   biometrics): permissive mode passes through (`true`, the legacy web behavior),
 *   strict mode refuses. Once the authenticator IS reachable, a denial or an unexpected
 *   ceremony error fails closed (`false`) — never mistaken for success.
 * - [KSafeBiometricsWeb.promptsEnabled]` = false` restores the pre-2.2.0 always-`true`
 *   no-op (the migration path for web apps that relied on the old pass-through).
 */

/** Ceremony ops, implemented per target ('js()' dispatcher vs '@JsFun'):
 *  "available"/null → "yes" | "no:<reason>"
 *  "register"/null  → "registered:<credIdB64url>" | "denied:<name>" | "error:<name>"
 *  "verify"/credId  → "verified" | "denied:<name>" | "error:<name>" */
internal expect suspend fun webAuthnCall(op: String, arg: String?): String

internal expect fun webBioLocalGet(key: String): String?
internal expect fun webBioLocalSet(key: String, value: String)
internal expect fun webBioLocalRemove(key: String)

/** Monotonic now (ms) — `performance.now()`; a wall-clock jump must not extend a cached auth. */
internal expect fun webBioMonotonicNowMs(): Double

/**
 * Web-only controls for [KSafeBiometrics] (visible from `jsMain`/`wasmJsMain` app code).
 */
object KSafeBiometricsWeb {
    /**
     * `false` restores the pre-2.2.0 always-`true` no-op — the web twin of the JVM
     * `-Dksafe.biometrics.jvm.prompts=off` opt-out (browsers have no system properties).
     */
    var promptsEnabled: Boolean = true

    /**
     * Forgets the stored WebAuthn credential id, so the next call re-registers.
     * Use when the user removed the passkey OS-side (every `verify` then fails as
     * denied) or to force a fresh enrollment.
     */
    fun resetRegistration() {
        webBioLocalRemove(WEBAUTHN_CREDENTIAL_ID_KEY)
    }
}

/** localStorage slot for the WebAuthn credential id (a public identifier, not a secret). */
internal const val WEBAUTHN_CREDENTIAL_ID_KEY = "__ksafe_biometrics_webauthn_id__"

/** Test seam: replaces the WebAuthn ceremony so unit tests never show real dialogs. */
internal var webAuthnCallOverrideForTest: (suspend (op: String, arg: String?) -> String)? = null

private suspend fun ceremony(op: String, arg: String?): String =
    webAuthnCallOverrideForTest?.invoke(op, arg) ?: webAuthnCall(op, arg)

// Single-threaded web still interleaves at suspension points; the gate keeps a second
// call from starting a concurrent WebAuthn ceremony (browsers reject overlapping ones).
private val promptGate = BiometricPromptGate()

private val biometricAuthSessions = mutableMapOf<String, Double>()

private val directCallbackScope = CoroutineScope(SupervisorJob())

private var warnedUnavailable = false
private fun warnUnavailableOnce(reason: String) {
    if (!warnedUnavailable) {
        warnedUnavailable = true
        println(
            "KSafe biometrics: WebAuthn platform authenticator unavailable ($reason) — " +
                "verifyBiometric passes through (allowDeviceCredentialFallback=true) or refuses (false)."
        )
    }
}

private suspend fun runWebAuthnGate(allowDeviceCredentialFallback: Boolean): Boolean {
    if (!KSafeBiometricsWeb.promptsEnabled) return true // legacy no-op, both modes

    val availability = ceremony("available", null)
    if (availability != "yes") {
        warnUnavailableOnce(availability)
        return allowDeviceCredentialFallback
    }

    val credentialId = webBioLocalGet(WEBAUTHN_CREDENTIAL_ID_KEY)
    val outcome = if (credentialId == null) ceremony("register", null) else ceremony("verify", credentialId)
    return when {
        outcome == "verified" -> true
        // First-use enrollment: create() verified the user as part of the ceremony.
        outcome.startsWith("registered:") -> {
            webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, outcome.removePrefix("registered:"))
            true
        }
        else -> false // denied:* and error:* — fail closed
    }
}

internal actual suspend fun platformVerifyBiometric(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
): Boolean {
    if (BiometricAuthSession.shouldCache(authorizationDuration)) {
        val scope = BiometricAuthSession.sessionKey(
            authorizationDuration!!.scope,
            requireStrict = !allowDeviceCredentialFallback,
        )
        val lastAuth = biometricAuthSessions[scope]
        if (lastAuth != null && (webBioMonotonicNowMs() - lastAuth) < authorizationDuration.duration) {
            return true
        }
    }

    val success = promptGate.withSinglePrompt { runWebAuthnGate(allowDeviceCredentialFallback) }

    if (success && BiometricAuthSession.shouldCache(authorizationDuration)) {
        seedBiometricSessionIfActive {
            biometricAuthSessions[
                BiometricAuthSession.sessionKey(
                    authorizationDuration!!.scope,
                    requireStrict = !allowDeviceCredentialFallback,
                )
            ] = webBioMonotonicNowMs()
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

internal actual suspend fun platformBiometricsAvailable(allowDeviceCredentialFallback: Boolean): Boolean {
    // The fallback flag is accepted for API symmetry only — WebAuthn user verification
    // is whatever the platform authenticator offers, so it cannot narrow the answer.
    if (!KSafeBiometricsWeb.promptsEnabled) return false
    return ceremony("available", null) == "yes"
}

internal actual fun platformBiometricsAvailableDirect(
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
) {
    directCallbackScope.launch {
        val result = runCatching {
            platformBiometricsAvailable(allowDeviceCredentialFallback)
        }.getOrDefault(false)
        onResult(result)
    }
}
