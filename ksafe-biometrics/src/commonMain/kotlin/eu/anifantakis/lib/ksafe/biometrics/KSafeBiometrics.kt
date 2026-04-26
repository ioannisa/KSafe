package eu.anifantakis.lib.ksafe.biometrics

/**
 * Standalone biometric authentication helper.
 *
 * `KSafeBiometrics` is a process-wide static API. Call its methods directly —
 * no instance, no DI wiring. Android initializes itself automatically via a
 * `ContentProvider` declared in the library's merged manifest; other
 * platforms have no init.
 *
 * The module is independent of `:ksafe`: use it on its own to gate any action,
 * or alongside `:ksafe` to require biometric verification before storage access.
 *
 * ## Example
 * ```kotlin
 * // Same call shape on every platform — no instance, no Context, no DI
 *
 * // Always prompt
 * val ok = KSafeBiometrics.verifyBiometric("Authenticate to delete account")
 *
 * // Cache successful auth for 60s within a scope
 * KSafeBiometrics.verifyBiometricDirect(
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
object KSafeBiometrics {

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
     * val ok = KSafeBiometrics.verifyBiometric("Authenticate to delete account")
     *
     * // Cache for 60s globally
     * val ok = KSafeBiometrics.verifyBiometric(
     *     reason = "Authenticate",
     *     authorizationDuration = BiometricAuthorizationDuration(60_000L)
     * )
     *
     * // Cache for 60s scoped to settings screen
     * val ok = KSafeBiometrics.verifyBiometric(
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
    ): Boolean = platformVerifyBiometric(reason, authorizationDuration)

    /**
     * Non-blocking variant of [verifyBiometric].
     *
     * ## Example
     * ```kotlin
     * KSafeBiometrics.verifyBiometricDirect("Authenticate") { success ->
     *     if (success) { /* … */ }
     * }
     *
     * KSafeBiometrics.verifyBiometricDirect(
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
    ) = platformVerifyBiometricDirect(reason, authorizationDuration, onResult)

    /**
     * Clears cached biometric authorization for a specific scope or all scopes.
     *
     * Use this to force re-authentication, for example on user logout.
     *
     * @param scope The scope to clear. If `null`, clears ALL cached authorizations.
     */
    fun clearBiometricAuth(scope: String? = null) = platformClearBiometricAuth(scope)
}

// ─── Platform helpers ──────────────────────────────────────────────────────
//
// `KSafeBiometrics` delegates to these per-platform top-level functions.
// Each platform owns its own session-cache state (Android/iOS: real cache;
// JVM/JS/WasmJS: no cache, always returns true).

internal expect suspend fun platformVerifyBiometric(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
): Boolean

internal expect fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    onResult: (Boolean) -> Unit,
)

internal expect fun platformClearBiometricAuth(scope: String?)

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
