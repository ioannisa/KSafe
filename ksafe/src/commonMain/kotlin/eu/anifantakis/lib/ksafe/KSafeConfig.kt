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
 * // Default configuration (AES-256, no user authentication)
 * val ksafe = KSafe(context)
 *
 * // Custom key size
 * val ksafe128 = KSafe(context, config = KSafeConfig(keySize = 128))
 *
 * // Require biometric/PIN authentication (Android only)
 * val secureSafe = KSafe(
 *     context,
 *     config = KSafeConfig(
 *         userAuthenticationRequired = true,
 *         userAuthenticationValiditySeconds = 30  // Key valid for 30 seconds after auth
 *     )
 * )
 * ```
 *
 * ## Biometric/PIN Authentication (Android Only)
 *
 * When [userAuthenticationRequired] is `true`, the user must authenticate (biometric or device PIN)
 * before the encryption key can be used. KSafe supports **Time-Bound authentication**:
 *
 * - Set [userAuthenticationValiditySeconds] to a positive value (e.g., 30 seconds)
 * - After the user unlocks the device or authenticates via BiometricPrompt, the key remains
 *   usable for the specified duration
 * - Your app should trigger authentication (e.g., show BiometricPrompt) before calling KSafe APIs
 *
 * **Note:** Per-operation authentication (validity = 0) is NOT supported because it requires
 * passing a CryptoObject through BiometricPrompt, which KSafe cannot do internally.
 *
 * @property keySize The size of the AES key in bits. Supported values: 128, 256. Default is 256.
 *           **Note:** 128-bit keys may offer marginally faster encryption on very old devices,
 *           but 256-bit is strongly recommended for all modern devices (negligible performance difference).
 * @property userAuthenticationRequired If true, the cryptographic key can only be used after
 *           the user has authenticated (Biometric/PIN). **Android only** - ignored on iOS/JVM.
 * @property userAuthenticationValiditySeconds Duration in seconds that the key remains usable
 *           after authentication. Must be a positive value when [userAuthenticationRequired] is true.
 *           Recommended: 10-60 seconds depending on your UX needs. **Android only**.
 */
data class KSafeConfig(
    val keySize: Int = 256,
    val userAuthenticationRequired: Boolean = false,
    val userAuthenticationValiditySeconds: Int = 30
) {
    init {
        require(keySize == 128 || keySize == 256) {
            "keySize must be 128 or 256 bits. Got: $keySize"
        }
        require(!userAuthenticationRequired || userAuthenticationValiditySeconds > 0) {
            "userAuthenticationValiditySeconds must be positive when userAuthenticationRequired is true. " +
            "Per-operation authentication (0 or negative values) is not supported. " +
            "Got: $userAuthenticationValiditySeconds"
        }
    }
}
