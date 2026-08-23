package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Web (Kotlin/JS + Kotlin/Wasm) implementation of [KSafeBiometrics] via WebAuthn platform
 * authenticators (`navigator.credentials`) as a local re-auth gate (self-generated challenge,
 * no server ceremony).
 *
 * Web-specific quirks:
 * - First use runs a one-time `create()` ceremony (which itself verifies the user) and stores
 *   the credential id in `localStorage`; later calls run `get()` against it.
 * - The `reason` string is NOT displayed — WebAuthn dialogs are browser-controlled and accept
 *   no custom message.
 * - Browsers may require transient activation — call from a click handler or the ceremony can be
 *   rejected (`NotAllowedError`).
 * - `allowDeviceCredentialFallback = false` cannot exclude the platform's PIN where the OS treats
 *   it as part of the authenticator (e.g. Windows Hello); it still keys the auth cache strictly.
 * - No platform authenticator: permissive mode passes through (`true`), strict mode refuses. Once
 *   the authenticator IS reachable, a denial or unexpected error fails closed (`false`).
 * - [KSafeBiometricsWeb.promptsEnabled]` = false` restores the pre-2.2.0 always-`true` no-op.
 */

/** Ceremony ops, implemented per target ('js()' dispatcher vs '@JsFun'):
 *  "available"/null → "yes" | "no:<reason>"
 *  "register"/null  → "registered:<credIdB64url>" | "denied:<name>" | "error:<name>"
 *  "verify"/credId  → "verified" | "denied:<name>" | "error:<name>" */
internal expect suspend fun webAuthnCall(op: String, arg: String?): String

/** Aborts the in-flight register/verify ceremony (its `AbortController`), synchronously. */
internal expect fun webAuthnAbort()

internal expect fun webBioLocalGet(key: String): String?
internal expect fun webBioLocalSet(key: String, value: String)
internal expect fun webBioLocalRemove(key: String)

/** Monotonic now (ms) — `performance.now()`; a wall-clock jump must not extend a cached auth. */
internal expect fun webBioMonotonicNowMs(): Double

/** Web-only controls for [KSafeBiometrics] (visible from `jsMain`/`wasmJsMain` app code). */
object KSafeBiometricsWeb {
    /** `false` restores the pre-2.2.0 always-`true` no-op — the web twin of the JVM prompts opt-out. */
    var promptsEnabled: Boolean = true

    /**
     * Forgets the stored WebAuthn credential id AND revokes every cached authorization window,
     * so the next call re-registers. Use when the user removed the passkey OS-side (every
     * `verify` then fails as denied) or to force fresh enrollment.
     */
    fun resetRegistration() {
        // Captured before the removal below, because it is the credential we are abandoning.
        val abandoned = runCatching { webBioLocalGet(WEBAUTHN_CREDENTIAL_ID_KEY) }.getOrNull()
        // Revoke BEFORE touching storage: every cached window was earned under the credential
        // being removed, and a throwing removeItem (storage-blocked browsers) must not leave
        // a live authorization that skips the promised fresh enrollment for its TTL.
        BiometricSessionStore.clear(null)
        webBioLocalRemove(WEBAUTHN_CREDENTIAL_ID_KEY)
        runCatching { webBioLocalRemove(WEBAUTHN_REGISTERED_TITLE_KEY) }
        abandoned?.let(::signalAbandonedCredential)
    }

    /**
     * Whether THIS ORIGIN holds a stored WebAuthn credential id — i.e. whether the next
     * verification would re-use a passkey instead of enrolling one.
     *
     * Reflects KSafe's own local record, NOT the authenticator's truth, and it is NEVER
     * invalidated automatically: a passkey the user deleted OS-side keeps reading `true` while
     * every verification fails, until the app calls [resetRegistration]. KSafe deliberately does
     * not self-heal — WebAuthn reports a cancelled prompt and an unrecognized credential as the
     * same `NotAllowedError` (so a site cannot probe for credentials), so discarding the
     * enrollment on failure would punish a user who merely pressed Cancel. Give the user a
     * "reset biometric unlock" affordance instead. Conversely, clearing site data reads `false`
     * while the passkey may survive, orphaned, in the password manager.
     */
    val isRegistered: Boolean
        get() = runCatching { webBioLocalGet(WEBAUTHN_CREDENTIAL_ID_KEY) }.getOrNull() != null

    /**
     * The title the stored passkey was registered under — what a password manager lists —
     * or `null` when nothing is registered, when it was enrolled without a title, or when it
     * predates this record (KSafe < 3.0.0).
     *
     * Lets an app that renames itself re-enroll exactly once instead of on every launch:
     * ```
     * if (KSafeBiometricsWeb.isRegistered &&
     *     KSafeBiometricsWeb.registeredTitle != KSafeBiometrics.defaultTitle
     * ) KSafeBiometricsWeb.resetRegistration()
     * ```
     * Renaming does not rename the existing passkey; the user should also delete the stale one
     * OS-side, or it lingers alongside the new entry.
     */
    val registeredTitle: String?
        get() = runCatching { webBioLocalGet(WEBAUTHN_REGISTERED_TITLE_KEY) }.getOrNull()
}

/** localStorage slot for the WebAuthn credential id (a public identifier, not a secret). */
internal const val WEBAUTHN_CREDENTIAL_ID_KEY = "__ksafe_biometrics_webauthn_id__"

/** localStorage slot for the title the stored passkey was registered under. */
internal const val WEBAUTHN_REGISTERED_TITLE_KEY = "__ksafe_biometrics_webauthn_title__"

internal var webAuthnCallOverrideForTest: (suspend (op: String, arg: String?) -> String)? = null
internal var webAuthnAbortOverrideForTest: (() -> Unit)? = null

private suspend fun ceremony(op: String, arg: String?): String =
    webAuthnCallOverrideForTest?.invoke(op, arg) ?: webAuthnCall(op, arg)

// A cancelled awaiter releases the prompt gate, but the browser's WebAuthn dialog stays up —
// abort the ceremony so the next caller can't start an overlapping (browser-rejected) one and
// a cancelled registration can't mint a credential whose id is never stored.
private suspend fun abortableCeremony(op: String, arg: String?): String =
    try {
        ceremony(op, arg)
    } catch (e: CancellationException) {
        webAuthnAbortOverrideForTest?.invoke() ?: webAuthnAbort()
        throw e
    }

// Gate serializes ceremonies: browsers reject overlapping WebAuthn calls, and single-threaded web
// still interleaves at suspension points.
private val promptGate = BiometricPromptGate()

private val directCallbackScope = CoroutineScope(SupervisorJob())

/**
 * Best-effort notice to the passkey provider that [credentialId] is no longer recognised, so it
 * can drop the credential a [KSafeBiometricsWeb.resetRegistration] abandons instead of leaving it
 * beside the next enrollment.
 *
 * Fire-and-forget by construction: [KSafeBiometricsWeb.resetRegistration] is not suspending, the
 * signal is advisory (each provider decides what to do with it), and every failure mode — a
 * browser without the API, a provider that ignores it, a rejection, or Safari 26's promise that
 * never settles — must leave the reset itself untouched. The timeout exists only so a
 * non-settling promise cannot accumulate a suspended coroutine per call.
 */
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

// Only AUTHENTICATED (a real ceremony) may seed the auth cache; a PASS_THROUGH must not, or a later
// cache hit would skip a real prompt once an authenticator becomes reachable.
private enum class WebAuthnGateResult { AUTHENTICATED, PASS_THROUGH, DENIED }

private suspend fun runWebAuthnGate(allowDeviceCredentialFallback: Boolean, title: String?): WebAuthnGateResult {
    if (!KSafeBiometricsWeb.promptsEnabled) return WebAuthnGateResult.PASS_THROUGH

    val availability = ceremony("available", null)
    if (availability != "yes") {
        warnUnavailableOnce(availability)
        return if (allowDeviceCredentialFallback) WebAuthnGateResult.PASS_THROUGH else WebAuthnGateResult.DENIED
    }

    // A blocked localStorage (SecurityError: "block all cookies", sandboxed iframe) must not
    // escape verifyBiometric's Boolean contract: treat the id as absent and run the register
    // ceremony, which itself verifies the user (its best-effort persist already tolerates
    // the same failure).
    val credentialId = runCatching { webBioLocalGet(WEBAUTHN_CREDENTIAL_ID_KEY) }.getOrNull()
    val outcome = if (credentialId == null) {
        // The title names the passkey the ceremony mints (rp.name / user.name / displayName) —
        // what a password manager lists. Written ONCE, at registration: a later title change
        // cannot rename an existing passkey (see KSafeBiometrics.defaultTitle).
        abortableCeremony("register", title)
    } else {
        abortableCeremony("verify", credentialId)
    }
    return when {
        outcome == "verified" -> WebAuthnGateResult.AUTHENTICATED
        // create() verified the user; persisting the id is best-effort — if setItem throws (storage
        // disabled / quota / legacy Safari private browsing) the verified user must still pass.
        outcome.startsWith("registered:") -> {
            runCatching { webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, outcome.removePrefix("registered:")) }
            // Record the name the passkey was minted under so an app that later changes its
            // title can detect the mismatch and re-enroll deliberately, instead of guessing.
            // Absent title -> slot removed, so a legacy record and a title-less one both read null.
            runCatching {
                if (title != null) webBioLocalSet(WEBAUTHN_REGISTERED_TITLE_KEY, title)
                else webBioLocalRemove(WEBAUTHN_REGISTERED_TITLE_KEY)
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

    // Re-check the cache INSIDE the gate: a caller we queued behind may have just seeded this scope,
    // so skip a redundant prompt (null → authorized, but don't re-seed, so the window can't extend).
    val result = promptGate.withSinglePrompt {
        if (attempt.isFresh()) {
            null
        } else {
            val outcome = runWebAuthnGate(allowDeviceCredentialFallback, title)
            // Seed while the gate is still HELD: a caller queued behind us re-checks freshness the
            // instant the gate changes hands, and seeding after the release leaves a window in
            // which it reads a cache we have not written yet and runs a second ceremony.
            // Seed only a REAL ceremony success — never a pass-through, a cache re-hit, nor a
            // success that landed after clearBiometricAuth()/resetRegistration() revoked the
            // scope mid-prompt.
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
    // The fallback flag is accepted for API symmetry only — WebAuthn user verification
    // is whatever the platform authenticator offers, so it cannot narrow the answer.
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
