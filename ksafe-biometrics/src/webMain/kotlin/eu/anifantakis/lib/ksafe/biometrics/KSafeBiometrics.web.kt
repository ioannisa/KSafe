package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

// WebAuthn platform authenticators used as a local re-auth gate: self-generated challenge, no
// server ceremony. The `reason` string is never shown (the browser owns the dialog), and browsers
// may require transient activation, so call from a click handler.

/** Ops: "available" → "yes"|"no:<reason>"; "register" → "registered:<credIdB64url>"|"denied:<n>"|"error:<n>";
 *  "verify"/credId → "verified"|"denied:<n>"|"error:<n>". */
internal expect suspend fun webAuthnCall(op: String, arg: String?): String

internal expect fun webAuthnAbort()

internal expect fun webBioLocalGet(key: String): String?
internal expect fun webBioLocalSet(key: String, value: String)
internal expect fun webBioLocalRemove(key: String)

/** Monotonic now (ms): a wall-clock jump must not extend a cached auth. */
internal expect fun webBioMonotonicNowMs(): Double

/** Web-only controls for [KSafeBiometrics] (visible from `jsMain`/`wasmJsMain` app code). */
object KSafeBiometricsWeb {
    /** `false` makes [KSafeBiometrics.verifyBiometric] a no-op returning `true` and
     *  [KSafeBiometrics.biometricsAvailable] report `false` — the web twin of the JVM
     *  `-Dksafe.biometrics.jvm.prompts=off` opt-out. */
    var promptsEnabled: Boolean = true

    /**
     * Forgets the stored credential id and revokes cached authorizations, so the next call
     * re-registers. Use it when the user deleted the passkey OS-side (every verification then
     * fails) or to force fresh enrollment. The browser is only advised that the old passkey is
     * unused, so it may linger in the password manager.
     */
    fun resetRegistration() {
        val abandoned = runCatching { webBioLocalGet(WEBAUTHN_CREDENTIAL_ID_KEY) }.getOrNull()
        // Revoke BEFORE touching storage: a throwing removeItem must not leave a live
        // authorization that outlives the credential it was earned under.
        BiometricSessionStore.clear(null)
        runCatching { localRemove(WEBAUTHN_CREDENTIAL_ID_KEY) }
        runCatching { localRemove(WEBAUTHN_REGISTERED_TITLE_KEY) }
        abandoned?.let(::signalAbandonedCredential)
    }

    /**
     * Whether this origin holds a stored credential id. Reflects KSafe's own record, not the
     * authenticator's: WebAuthn reports a cancelled prompt and an unknown credential identically,
     * so a passkey deleted OS-side keeps reading `true` until [resetRegistration] is called.
     */
    val isRegistered: Boolean
        get() = runCatching { webBioLocalGet(WEBAUTHN_CREDENTIAL_ID_KEY) }.getOrNull() != null

    /**
     * The title the stored passkey was registered under, or `null` if nothing is registered or it
     * was enrolled without one. An app that renames itself can compare it against its current
     * title and call [resetRegistration] once, instead of re-enrolling on every launch.
     */
    val registeredTitle: String?
        get() = runCatching { webBioLocalGet(WEBAUTHN_REGISTERED_TITLE_KEY) }.getOrNull()
}

/** localStorage slot for the credential id — a public identifier, not a secret. */
internal const val WEBAUTHN_CREDENTIAL_ID_KEY = "__ksafe_biometrics_webauthn_id__"

internal const val WEBAUTHN_REGISTERED_TITLE_KEY = "__ksafe_biometrics_webauthn_title__"

internal var webAuthnCallOverrideForTest: (suspend (op: String, arg: String?) -> String)? = null
internal var webAuthnAbortOverrideForTest: (() -> Unit)? = null
internal var webBioLocalRemoveOverrideForTest: ((key: String) -> Unit)? = null

private fun localRemove(key: String) {
    val override = webBioLocalRemoveOverrideForTest
    if (override != null) override(key) else webBioLocalRemove(key)
}

private suspend fun ceremony(op: String, arg: String?): String =
    webAuthnCallOverrideForTest?.invoke(op, arg) ?: webAuthnCall(op, arg)

// A cancelled awaiter releases the gate but the browser dialog stays up: abort, or the next caller
// starts an overlapping ceremony and a cancelled registration mints a credential nobody stored.
private suspend fun abortableCeremony(op: String, arg: String?): String =
    try {
        ceremony(op, arg)
    } catch (e: CancellationException) {
        webAuthnAbortOverrideForTest?.invoke() ?: webAuthnAbort()
        throw e
    }

// Browsers reject overlapping WebAuthn calls, and single-threaded web still interleaves at suspends.
private val promptGate = BiometricPromptGate()

private val directCallbackScope = CoroutineScope(SupervisorJob())

// Advisory notice that the credential is abandoned. Fire-and-forget: the reset must survive every
// failure, and the timeout only stops a never-settling promise from parking a coroutine per call.
private fun signalAbandonedCredential(credentialId: String) {
    directCallbackScope.launch {
        runCatching { withTimeoutOrNull(SIGNAL_TIMEOUT_MS) { ceremony("signalUnknown", credentialId) } }
    }
}

private const val SIGNAL_TIMEOUT_MS = 5_000L

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

// Only AUTHENTICATED may seed the auth cache; seeding a PASS_THROUGH would skip a later real prompt.
private enum class WebAuthnGateResult { AUTHENTICATED, PASS_THROUGH, DENIED }

private suspend fun runWebAuthnGate(allowDeviceCredentialFallback: Boolean, title: String?): WebAuthnGateResult {
    if (!KSafeBiometricsWeb.promptsEnabled) return WebAuthnGateResult.PASS_THROUGH

    val availability = ceremony("available", null)
    if (availability != "yes") {
        warnUnavailableOnce(availability)
        return if (allowDeviceCredentialFallback) WebAuthnGateResult.PASS_THROUGH else WebAuthnGateResult.DENIED
    }

    // Blocked localStorage (SecurityError) must not escape verifyBiometric's Boolean contract:
    // treat the id as absent and register, which itself verifies the user.
    val credentialId = runCatching { webBioLocalGet(WEBAUTHN_CREDENTIAL_ID_KEY) }.getOrNull()
    val outcome = if (credentialId == null) {
        // The title names the passkey this mints; a later title change cannot rename an existing one.
        abortableCeremony("register", title)
    } else {
        abortableCeremony("verify", credentialId)
    }
    return when {
        outcome == "verified" -> WebAuthnGateResult.AUTHENTICATED
        // create() verified the user, so a throwing setItem must still let that user pass.
        outcome.startsWith("registered:") -> {
            runCatching { webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, outcome.removePrefix("registered:")) }
            // Absent title -> slot removed, so a legacy record and a title-less one both read null.
            runCatching {
                if (title != null) webBioLocalSet(WEBAUTHN_REGISTERED_TITLE_KEY, title)
                else localRemove(WEBAUTHN_REGISTERED_TITLE_KEY)
            }
            WebAuthnGateResult.AUTHENTICATED
        }
        else -> WebAuthnGateResult.DENIED // fail closed
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
    val result = promptGate.withSinglePrompt {
        if (attempt.isFresh()) {
            null
        } else {
            val outcome = runWebAuthnGate(allowDeviceCredentialFallback, title)
            // Seed while the gate is still HELD: a queued caller re-checks freshness the instant
            // the gate changes hands. Real ceremony only — never a pass-through or a revoked scope.
            if (outcome == WebAuthnGateResult.AUTHENTICATED) attempt.seedIfActive()
            outcome
        }
    }

    return result != WebAuthnGateResult.DENIED
}

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    title: String?,
    cancelLabel: String?,
    onResult: (Boolean) -> Unit,
) {
    directCallbackScope.deliverBiometricResult(onResult) {
        platformVerifyBiometric(reason, authorizationDuration, allowDeviceCredentialFallback, title, cancelLabel)
    }
}

internal actual suspend fun platformBiometricsAvailable(allowDeviceCredentialFallback: Boolean): Boolean {
    // Fallback flag accepted for API symmetry only: it cannot narrow WebAuthn user verification.
    if (!KSafeBiometricsWeb.promptsEnabled) return false
    return ceremony("available", null) == "yes"
}

internal actual fun platformBiometricsAvailableDirect(
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
) {
    directCallbackScope.deliverBiometricResult(onResult) {
        platformBiometricsAvailable(allowDeviceCredentialFallback)
    }
}
