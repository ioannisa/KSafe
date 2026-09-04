package eu.anifantakis.lib.ksafe.biometrics

/**
 * Process-wide static API for biometric authentication — no instance, no DI, zero-config init.
 * Real prompts on Android, iOS, macOS, and (since 2.2.0) JVM Desktop and the web:
 * JVM-on-macOS shows Touch ID / password via `LocalAuthentication`, JVM-on-Windows shows
 * Windows Hello via `UserConsentVerifier`, and JS/WasmJS show the browser's WebAuthn
 * platform-authenticator prompt (Touch ID / Windows Hello / fingerprint) when one exists.
 * JVM hosts with no prompt API (Linux) return `true`.
 *
 * **Security note:** where no prompt path exists (JVM on Linux, browsers without a platform
 * authenticator in permissive mode, or the opt-outs — `-Dksafe.biometrics.jvm.prompts=off`
 * on desktop, `KSafeBiometricsWeb.promptsEnabled = false` on web), the call returns `true` —
 * an unconditional pass — so shared `commonMain` logic can call in without branching. If you
 * need a hard refusal there, gate the call in your own code.
 */
@Suppress("unused")
object KSafeBiometrics {

    /**
     * App/service name shown to the user, and the default for [verifyBiometric]'s `title`.
     * Set it once at startup.
     *
     * Consumed per platform: Android uses it as the prompt title; the web uses it to NAME THE
     * PASSKEY (its `rp.name`, `user.name` and `user.displayName`), which is what a password
     * manager lists. Apple and JVM prompts have no title — they show only the reason — so they
     * ignore it. `null` keeps each platform's own default.
     *
     * **Web caveat:** the passkey's name is written ONCE, during the first registration
     * ceremony. Changing this later does not rename an existing passkey — that needs
     * `KSafeBiometricsWeb.resetRegistration()` (and removing the stale passkey OS-side). So set
     * it BEFORE the first [verifyBiometric] call, next to `awaitCacheReady()`.
     */
    var defaultTitle: String? = null

    /**
     * Default `reason` for [verifyBiometric] / [verifyBiometricDirect] — why authentication is
     * being asked. Shown as the Android subtitle, Apple's `localizedReason`, and the JVM
     * Windows-Hello / macOS message. Ignored on the web (the browser owns that dialog's text).
     * Set it at startup so the built-in English string never reaches a localized app.
     */
    var defaultReason: String = DEFAULT_BIOMETRIC_REASON

    /**
     * Default label for the prompt's cancel/negative button. `null` (default) uses the
     * platform's own LOCALIZED string — Android's `android.R.string.cancel`, Apple's system
     * default — so leave it null unless you deliberately want different wording; a hardcoded
     * value here would ship one language to every locale.
     *
     * **Android only applies this when `allowDeviceCredentialFallback = false`.** With the
     * fallback on (the default) the platform forbids a negative button entirely — the slot is
     * occupied by its own "use PIN/pattern/password" affordance — so there is no button to
     * relabel and this value is ignored. Blank is treated as unset on every platform.
     */
    var defaultCancelLabel: String? = null

    /**
     * Suspends until the biometric prompt completes: `true` on success, `false` on failed or
     * denied authentication (including the user dismissing the prompt). Cancelling the calling
     * coroutine does NOT return `false` — the call is cancelled (`CancellationException`
     * propagates) and any pending native prompt is dismissed/aborted.
     *
     * @param authorizationDuration When set, a successful authentication is cached for the
     *        given duration/scope and calls within it skip the prompt; `null` always prompts.
     * @param allowDeviceCredentialFallback When `true` (default), device credentials
     *        (PIN/password/pattern, or login password/Apple Watch on macOS) are accepted as
     *        fallback; `false` restricts to biometrics only. Ignored on JS/WasmJS. On
     *        JVM-Windows the Hello PIN counts as Hello itself, so `false` cannot exclude
     *        it (it still keys the authorization cache strictly and refuses when Hello
     *        is absent).
     * @param title Per-call override of [defaultTitle] — Android prompt title / web passkey
     *        name; ignored on Apple and JVM. See [defaultTitle] for the web's write-once caveat.
     * @param cancelLabel Per-call override of [defaultCancelLabel]; `null` or blank keeps the
     *        platform's localized default. Android applies it only when
     *        [allowDeviceCredentialFallback] is `false` — see [defaultCancelLabel].
     */
    suspend fun verifyBiometric(
        reason: String = defaultReason,
        authorizationDuration: BiometricAuthorizationDuration? = null,
        allowDeviceCredentialFallback: Boolean = true,
        title: String? = defaultTitle,
        cancelLabel: String? = defaultCancelLabel,
    ): Boolean = platformVerifyBiometric(
        promptReason(reason), authorizationDuration, allowDeviceCredentialFallback,
        promptTextOrNull(title), promptTextOrNull(cancelLabel),
    )

    /**
     * Non-blocking variant of [verifyBiometric]; delivers the result via [onResult].
     */
    fun verifyBiometricDirect(
        reason: String = defaultReason,
        authorizationDuration: BiometricAuthorizationDuration? = null,
        allowDeviceCredentialFallback: Boolean = true,
        title: String? = defaultTitle,
        cancelLabel: String? = defaultCancelLabel,
        onResult: (Boolean) -> Unit,
    ) = platformVerifyBiometricDirect(
        promptReason(reason), authorizationDuration, allowDeviceCredentialFallback,
        promptTextOrNull(title), promptTextOrNull(cancelLabel), onResult,
    )

    /**
     * Clears cached biometric authorization for [scope], or all scopes when `null`.
     * Also revokes prompts already on screen: if one completes successfully after this
     * call, its caller still gets `true`, but the success cannot re-seed the cache —
     * the next protected call prompts again.
     */
    fun clearBiometricAuth(scope: String? = null) = BiometricSessionStore.clear(scope)

    /**
     * Whether [verifyBiometric] would show a REAL authentication prompt here — `false`
     * means the call would pass through (permissive) or refuse (strict) without any
     * prompt, so the app can route to an alternative flow (its own PIN screen, a
     * password, …) instead of relying on a gate that doesn't gate.
     *
     * `false` on: JVM Linux (no prompt API), the opt-outs
     * (`-Dksafe.biometrics.jvm.prompts=off`, `KSafeBiometricsWeb.promptsEnabled = false`),
     * devices with nothing to prompt (no enrolled biometrics/credentials per
     * [allowDeviceCredentialFallback]), insecure web contexts, and the iOS Simulator
     * (where [verifyBiometric] is a pass-through).
     *
     * Suspending because the browser (WebAuthn) and Windows (Hello) can only answer
     * asynchronously; the check never shows UI and needs no user gesture, so probe it
     * once at startup (on web, right next to `awaitCacheReady()`) and keep the result
     * in app state for synchronous `if (available)` use everywhere.
     *
     * @param allowDeviceCredentialFallback mirror of [verifyBiometric]'s parameter:
     *        `true` asks "would the default permissive prompt show", `false` asks
     *        "is a biometrics-only prompt possible".
     */
    suspend fun biometricsAvailable(allowDeviceCredentialFallback: Boolean = true): Boolean =
        platformBiometricsAvailable(allowDeviceCredentialFallback)

    /**
     * Non-suspending variant of [biometricsAvailable]; delivers the result via [onResult].
     */
    fun biometricsAvailableDirect(
        allowDeviceCredentialFallback: Boolean = true,
        onResult: (Boolean) -> Unit,
    ) = platformBiometricsAvailableDirect(allowDeviceCredentialFallback, onResult)
}

// The per-platform actuals below share an authorization cache; it lives in BiometricSessionStore.

internal expect suspend fun platformVerifyBiometric(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    title: String?,
    cancelLabel: String?,
): Boolean

internal expect fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    title: String?,
    cancelLabel: String?,
    onResult: (Boolean) -> Unit,
)

internal expect suspend fun platformBiometricsAvailable(allowDeviceCredentialFallback: Boolean): Boolean

internal expect fun platformBiometricsAvailableDirect(
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
)

/**
 * Caches a successful authentication so calls within the window skip the prompt.
 *
 * @property duration Validity window in milliseconds; must be greater than 0 to cache.
 * @property scope Cache scope — different scopes keep separate timestamps; `null` (default)
 *           is the global scope shared across all calls.
 */
data class BiometricAuthorizationDuration(
    val duration: Long,
    val scope: String? = null
)
