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
 *
 * // Android: customize biometric auth validity duration
 * val androidSafe = KSafe(
 *     context,
 *     config = KSafeConfig(androidAuthValiditySeconds = 60)
 * )
 * ```
 *
 * ## Biometric Protection
 *
 * Biometric protection is configured **per-value**, not at the KSafe instance level:
 *
 * ```kotlin
 * val ksafe = KSafe(context)
 *
 * // Per-value biometric protection
 * var authToken by ksafe(defaultValue = "", encrypted = true, useBiometrics = true)  // 🔐 Protected
 * var theme by ksafe(defaultValue = "light", encrypted = false)  // Not protected
 * ```
 *
 * Platform behavior when `useBiometrics = true`:
 *
 * | Platform | Behavior |
 * |----------|----------|
 * | **Android** | Time-bound: Key usable for N seconds after BiometricPrompt/device unlock |
 * | **iOS** | Per-access: Face ID / Touch ID / Passcode prompt on each key access |
 * | **JVM** | Ignored (no biometric hardware available) |
 *
 * @property keySize The size of the AES key in bits. Supported values: 128, 256. Default is 256.
 *           **Note:** 128-bit keys may offer marginally faster encryption on very old devices,
 *           but 256-bit is strongly recommended for all modern devices (negligible performance difference).
 * @property androidAuthValiditySeconds **Android only.** Duration in seconds that biometric-protected
 *           keys remain usable after authentication. Default is 30 seconds. Ignored on iOS/JVM.
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
