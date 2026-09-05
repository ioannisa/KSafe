package eu.anifantakis.lib.ksafe.biometrics

/**
 * Process-wide biometric authentication — no instance, no DI. Real prompts on Android, iOS,
 * macOS, JVM Desktop (Touch ID / Windows Hello) and the web (WebAuthn). Where no prompt path
 * exists (JVM on Linux, the iOS Simulator, browsers without a platform authenticator while the
 * credential fallback is on, or the opt-outs `-Dksafe.biometrics.jvm.prompts=off` and
 * `KSafeBiometricsWeb.promptsEnabled = false`) [verifyBiometric] returns `true` rather than
 * refusing, so shared code needs no branching; ask [biometricsAvailable] when that matters.
 */
@Suppress("unused")
object KSafeBiometrics {

    /** App/service name shown to the user, and the default for [verifyBiometric]'s `title`.
     *  Android uses it as the prompt title, the web to name the passkey; Apple and JVM ignore it.
     *  `null` keeps each platform's own default. The web writes the passkey name once, so set
     *  this before the first [verifyBiometric] call. */
    var defaultTitle: String? = null

    /** Default `reason` — why authentication is being asked. Shown as the Android subtitle,
     *  Apple's `localizedReason` and the JVM message; ignored on the web. Blank falls back to
     *  the built-in English text. */
    var defaultReason: String = DEFAULT_BIOMETRIC_REASON

    /** Label for the prompt's cancel button; `null` or blank uses the platform's localized one.
     *  Android applies it only when `allowDeviceCredentialFallback = false` — with the fallback
     *  on, the platform forbids a negative button. Ignored on JVM and the web. */
    var defaultCancelLabel: String? = null

    /**
     * Suspends until the prompt completes: `true` on success, `false` on failure or dismissal.
     * Returns `true` without a prompt while a cached authorization for [authorizationDuration]
     * is live. Callable from any dispatcher; concurrent calls queue behind one prompt.
     * Cancelling the caller propagates `CancellationException` instead of returning `false`.
     *
     * @param reason Why authentication is asked; see [defaultReason].
     * @param authorizationDuration Caches a success for that duration/scope; `null` always prompts.
     * @param allowDeviceCredentialFallback `true` (default) also accepts PIN/password/pattern.
     *        Ignored on JS/WasmJS; on JVM-Windows the Hello PIN counts as Hello itself.
     * @param title Android prompt title / web passkey name; ignored on Apple and JVM.
     * @param cancelLabel Cancel button text; see [defaultCancelLabel] for where it applies.
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

    /** Callback-style [verifyBiometric] for non-coroutine callers. [onResult] runs on the main
     *  thread on Android and Apple, on a background thread on JVM. */
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

    /** Clears cached authorization for [scope], or all scopes when `null`. A prompt already on
     *  screen still returns `true` to its caller, but can no longer re-seed the cache. */
    fun clearBiometricAuth(scope: String? = null) = BiometricSessionStore.clear(scope)

    /**
     * Whether [verifyBiometric] would show a real prompt here; `false` means it would pass
     * through without one, so the app can route to its own PIN flow. Shows no UI, so probe it
     * once at startup and keep the answer — but on Android probe from a composition or an
     * Activity, since `Application.onCreate` has no host yet and would cache a permanent `false`.
     */
    suspend fun biometricsAvailable(allowDeviceCredentialFallback: Boolean = true): Boolean =
        platformBiometricsAvailable(allowDeviceCredentialFallback)

    /** Callback-style [biometricsAvailable]. [onResult] runs on the main thread on Android and
     *  Apple, on a background thread on JVM. */
    fun biometricsAvailableDirect(
        allowDeviceCredentialFallback: Boolean = true,
        onResult: (Boolean) -> Unit,
    ) = platformBiometricsAvailableDirect(allowDeviceCredentialFallback, onResult)
}

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
 * Caches a successful authentication so calls within the window skip the prompt. Strict and
 * permissive calls (`allowDeviceCredentialFallback`) keep separate entries; drop them early
 * with [KSafeBiometrics.clearBiometricAuth].
 *
 * @property duration Window in milliseconds; must be greater than 0 to cache.
 * @property scope Separate scopes keep separate timestamps; `null` is the global scope.
 */
data class BiometricAuthorizationDuration(
    val duration: Long,
    val scope: String? = null
)
