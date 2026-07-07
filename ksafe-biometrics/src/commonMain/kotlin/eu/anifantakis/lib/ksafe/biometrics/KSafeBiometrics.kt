package eu.anifantakis.lib.ksafe.biometrics

/**
 * Process-wide static API for biometric authentication — no instance, no DI, zero-config init
 * (real prompts on Android/iOS/macOS; JVM/JS/WasmJS have no hardware and always return `true`).
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
     *        fallback; `false` restricts to biometrics only. Ignored on JVM/JS/WasmJS.
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
