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
 *         userAuthenticationValiditySeconds = 30
 *     )
 * )
 * ```
 *
 * @property keySize The size of the AES key in bits. Supported values: 128, 256. Default is 256.
 *           **Note:** 128-bit keys may offer marginally faster encryption on very old devices,
 *           but 256-bit is strongly recommended for all modern devices (negligible performance difference).
 * @property userAuthenticationRequired If true, the cryptographic key can only be used after
 *           the user has authenticated (Biometric/PIN). **Android only** - ignored on iOS/JVM.
 * @property userAuthenticationValiditySeconds Duration in seconds that the key remains usable
 *           after authentication. Use -1 for "valid for the duration of the authentication session".
 *           Only applicable when [userAuthenticationRequired] is true. **Android only**.
 */
data class KSafeConfig(
    val keySize: Int = 256,
    val userAuthenticationRequired: Boolean = false,
    val userAuthenticationValiditySeconds: Int = -1
) {
    init {
        require(keySize == 128 || keySize == 256) {
            "keySize must be 128 or 256 bits. Got: $keySize"
        }
    }
}
