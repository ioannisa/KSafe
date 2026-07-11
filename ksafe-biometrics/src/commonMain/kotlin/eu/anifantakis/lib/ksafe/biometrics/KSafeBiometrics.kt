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
     * Suspends until the biometric prompt completes, returning `true` on success and `false`
     * on failure or cancellation.
     *
     * @param authorizationDuration When set, a successful authentication is cached for the
     *        given duration/scope and calls within it skip the prompt; `null` always prompts.
     * @param allowDeviceCredentialFallback When `true` (default), device credentials
     *        (PIN/password/pattern, or login password/Apple Watch on macOS) are accepted as
     *        fallback; `false` restricts to biometrics only. Ignored on JS/WasmJS. On
     *        JVM-Windows the Hello PIN counts as Hello itself, so `false` cannot exclude
     *        it (it still keys the authorization cache strictly and refuses when Hello
     *        is absent).
     */
    suspend fun verifyBiometric(
        reason: String = "Authenticate to continue",
        authorizationDuration: BiometricAuthorizationDuration? = null,
        allowDeviceCredentialFallback: Boolean = true,
    ): Boolean = platformVerifyBiometric(reason, authorizationDuration, allowDeviceCredentialFallback)

    /**
     * Non-blocking variant of [verifyBiometric]; delivers the result via [onResult].
     */
    fun verifyBiometricDirect(
        reason: String = "Authenticate to continue",
        authorizationDuration: BiometricAuthorizationDuration? = null,
        allowDeviceCredentialFallback: Boolean = true,
        onResult: (Boolean) -> Unit,
    ) = platformVerifyBiometricDirect(reason, authorizationDuration, allowDeviceCredentialFallback, onResult)

    /**
     * Clears cached biometric authorization for [scope], or all scopes when `null`.
     */
    fun clearBiometricAuth(scope: String? = null) = platformClearBiometricAuth(scope)

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

// Per-platform implementations backing [KSafeBiometrics]; each platform owns its cache state.

internal expect suspend fun platformVerifyBiometric(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
): Boolean

internal expect fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
)

internal expect fun platformClearBiometricAuth(scope: String?)

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
