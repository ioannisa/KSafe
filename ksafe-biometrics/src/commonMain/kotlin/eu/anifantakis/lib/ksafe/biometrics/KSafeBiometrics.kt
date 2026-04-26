package eu.anifantakis.lib.ksafe.biometrics

/**
 * Standalone biometric authentication helper.
 *
 * `KSafeBiometrics` is an independent module — it has no dependency on the
 * `:ksafe` storage library and can be used on its own. Use it alongside
 * KSafe when you want to gate storage access (or any other action) behind
 * biometric verification.
 *
 * ## Example
 * ```kotlin
 * // Android: pass the application context
 * val biometrics = KSafeBiometrics(context)
 *
 * // iOS / JVM / web: no platform deps
 * val biometrics = KSafeBiometrics()
 *
 * // Always prompt
 * val ok = biometrics.verifyBiometric("Authenticate to delete account")
 *
 * // Cache successful auth for 60s within a scope
 * biometrics.verifyBiometricDirect(
 *     reason = "Authenticate",
 *     authorizationDuration = BiometricAuthorizationDuration(60_000L, "settings")
 * ) { success -> /* ... */ }
 * ```
 *
 * ## Platform behaviour
 * - **Android:** real `BiometricPrompt` (BIOMETRIC_STRONG + DEVICE_CREDENTIAL).
 *   Requires a `FragmentActivity` / `AppCompatActivity` to be visible.
 * - **iOS:** real Face ID / Touch ID via `LAContext`. Returns `true` on the simulator
 *   (no biometric hardware available).
 * - **JVM, JS, WasmJS:** no biometric hardware. All calls return `true` so shared
 *   business logic in `commonMain` can call into this module without branching.
 *   If you need a hard refusal on these platforms, gate the call in your own code.
 */
@Suppress("unused")
expect class KSafeBiometrics {

    /**
     * Verifies biometric authentication.
     *
     * Suspends until the user completes (or cancels) the prompt. Use [authorizationDuration]
     * to skip the prompt when a recent successful authentication is still valid for the
     * given scope.
     *
     * ## Example
     * ```kotlin
     * // Always prompt
     * val ok = biometrics.verifyBiometric("Authenticate to delete account")
     *
     * // Cache for 60s globally
     * val ok = biometrics.verifyBiometric(
     *     reason = "Authenticate",
     *     authorizationDuration = BiometricAuthorizationDuration(60_000L)
     * )
     *
     * // Cache for 60s scoped to settings screen
     * val ok = biometrics.verifyBiometric(
     *     reason = "Authenticate",
     *     authorizationDuration = BiometricAuthorizationDuration(60_000L, "settings-screen")
     * )
     * ```
     *
     * @param reason The reason shown to the user for the biometric prompt.
     * @param authorizationDuration Optional duration configuration for caching successful
     *        authentication. If `null` (default), authentication is required every time.
     * @return `true` if authentication succeeded, `false` if it failed or was cancelled.
     */
    suspend fun verifyBiometric(
        reason: String = "Authenticate to continue",
        authorizationDuration: BiometricAuthorizationDuration? = null
    ): Boolean

    /**
     * Non-blocking variant of [verifyBiometric].
     *
     * ## Example
     * ```kotlin
     * biometrics.verifyBiometricDirect("Authenticate") { success ->
     *     if (success) { /* … */ }
     * }
     *
     * biometrics.verifyBiometricDirect(
     *     reason = "Authenticate to save",
     *     authorizationDuration = BiometricAuthorizationDuration(60_000L)
     * ) { success -> /* ... */ }
     * ```
     *
     * @param reason The reason shown to the user for the biometric prompt.
     * @param authorizationDuration Optional duration configuration for caching successful
     *        authentication. If `null` (default), authentication is required every time.
     * @param onResult Callback with `true` on success, `false` on failure or cancellation.
     */
    fun verifyBiometricDirect(
        reason: String = "Authenticate to continue",
        authorizationDuration: BiometricAuthorizationDuration? = null,
        onResult: (Boolean) -> Unit
    )

    /**
     * Clears cached biometric authorization for a specific scope or all scopes.
     *
     * Use this to force re-authentication, for example on user logout.
     *
     * @param scope The scope to clear. If `null`, clears ALL cached authorizations.
     */
    fun clearBiometricAuth(scope: String? = null)
}

/**
 * Configuration for biometric authorization duration caching.
 *
 * When provided to [KSafeBiometrics.verifyBiometric] or [KSafeBiometrics.verifyBiometricDirect],
 * successful authentication is cached for the specified duration. Subsequent calls within
 * that duration (and same scope) return `true` without showing a biometric prompt.
 *
 * ## Examples
 * ```kotlin
 * // Cache for 60 seconds (global scope — any call benefits)
 * BiometricAuthorizationDuration(60_000L)
 *
 * // Cache for 60 seconds (scoped to "settings" — only settings calls benefit)
 * BiometricAuthorizationDuration(60_000L, "settings")
 *
 * // Cache for 5 minutes (scoped to user — invalidates on user change)
 * BiometricAuthorizationDuration(300_000L, "user_$userId")
 *
 * // Cache for 60 seconds (screen instance scope — invalidates on navigation)
 * BiometricAuthorizationDuration(60_000L, "screen_${viewModel.hashCode()}")
 * ```
 *
 * @property duration Duration in milliseconds for which the authentication remains valid.
 *           Must be greater than 0.
 * @property scope Optional scope identifier for the authorization session. Different scopes
 *           maintain separate authorization timestamps. Use this to invalidate cached auth
 *           when context changes:
 *           - `null` (default): Global scope, shared across all calls
 *           - Screen ID: Auth valid only while on that screen
 *           - User ID: Auth invalidated on user change
 *           - Random UUID: Forces fresh auth every time (when scope changes)
 */
data class BiometricAuthorizationDuration(
    val duration: Long,
    val scope: String? = null
)
