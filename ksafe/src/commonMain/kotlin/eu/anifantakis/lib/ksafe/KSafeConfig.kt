package eu.anifantakis.lib.ksafe

/**
 * Configuration for KSafe encryption parameters.
 *
 * This allows customization of the underlying encryption without compromising security.
 * The encryption algorithm (AES-GCM) and block mode are intentionally NOT configurable
 * to prevent insecure configurations.
 *
 * ## Example
 * ```kotlin
 * // Default configuration (AES-256)
 * val ksafe = KSafe(context)
 *
 * // Custom key size
 * val ksafe128 = KSafe(context, config = KSafeConfig(keySize = 128))
 * ```
 *
 * ## Biometric Authentication
 *
 * Biometric authentication is a **standalone helper** decoupled from storage operations.
 * Use `verifyBiometric()` or `verifyBiometricDirect()` to protect any action:
 *
 * ```kotlin
 * val ksafe = KSafe(context)
 *
 * // Protect storage with biometrics
 * ksafe.verifyBiometricDirect("Authenticate to save") { success ->
 *     if (success) {
 *         ksafe.putDirect("authToken", token)
 *     }
 * }
 *
 * // With duration caching (60 seconds, scoped to ViewModel)
 * ksafe.verifyBiometricDirect(
 *     reason = "Authenticate",
 *     authorizationDuration = BiometricAuthorizationDuration(60_000L, viewModelScope.hashCode().toString())
 * ) { success ->
 *     if (success) { /* ... */ }
 * }
 * ```
 *
 * | Platform | Behavior |
 * |----------|----------|
 * | **Android** | BiometricPrompt with fingerprint/face/device credential |
 * | **iOS** | Face ID / Touch ID / Passcode via LocalAuthentication |
 * | **JVM** | Always returns true (no biometric hardware available) |
 *
 * @property keySize The size of the AES key in bits. Supported values: 128, 256. Default is 256.
 *           **Note:** 128-bit keys may offer marginally faster encryption on very old devices,
 *           but 256-bit is strongly recommended for all modern devices (negligible performance difference).
 * @property androidAuthValiditySeconds Reserved for future use. Default is 30 seconds.
 */
data class KSafeConfig(
    val keySize: Int = 256,
    val androidAuthValiditySeconds: Int = 30
) {
    init {
        require(keySize == 128 || keySize == 256) {
            "keySize must be 128 or 256 bits. Got: $keySize"
        }
        require(androidAuthValiditySeconds > 0) {
            "androidAuthValiditySeconds must be positive. Got: $androidAuthValiditySeconds"
        }
    }
}
