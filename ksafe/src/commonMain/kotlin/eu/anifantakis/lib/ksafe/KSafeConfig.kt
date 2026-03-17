package eu.anifantakis.lib.ksafe

import kotlinx.serialization.json.Json

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
 * @property requireUnlockedDevice Default unlock policy for encrypted writes when using
 *           no-mode APIs (`put/putDirect` without explicit [KSafeWriteMode]).
 *
 *   | Platform    | `false` (default)                                  | `true`                                           |
 *   |-------------|----------------------------------------------------|-------------------------------------------------|
 *   | **Android** | Keys accessible at any time (no lock restriction)  | Keys created with `setUnlockedDeviceRequired(true)` (API 28+) |
 *   | **iOS**     | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`   |
 *   | **JVM**     | No effect (software-backed keys)                   | No effect (software-backed keys)                 |
 *
 *   For per-entry control, prefer [KSafeWriteMode.Encrypted] and set
 *   `requireUnlockedDevice` explicitly on each write.
 * @property json The [Json] instance used for serializing and deserializing user payloads.
 *           Override this to register a custom [kotlinx.serialization.modules.SerializersModule]
 *           for `@Contextual` types (e.g., `UUID`, `Instant`) or to change JSON behaviour
 *           (e.g., `encodeDefaults`, `coerceInputValues`).
 *
 *           **Important:** changing the format for an existing `fileName` namespace may make
 *           previously stored non-primitive values unreadable.
 *
 *           Defaults to [KSafeDefaults.json] (`Json { ignoreUnknownKeys = true }`).
 */
data class KSafeConfig(
    val keySize: Int = 256,
    val androidAuthValiditySeconds: Int = 30,
    val requireUnlockedDevice: Boolean = false,
    val json: Json = KSafeDefaults.json
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

/**
 * Shared defaults for KSafe configuration.
 */
object KSafeDefaults {
    /**
     * The default [Json] instance used for user-payload serialization.
     *
     * Uses `ignoreUnknownKeys = true` for forward/backward compatibility.
     */
    val json: Json = Json { ignoreUnknownKeys = true }
}
