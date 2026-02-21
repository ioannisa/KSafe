package eu.anifantakis.lib.ksafe

/**
 * Defines the encryption and key-storage protection level for a KSafe property.
 *
 * Use this enum with the `protection` parameter on KSafe API methods to control
 * per-property encryption behavior:
 *
 * ```kotlin
 * var counter by ksafe(0)                                                // DEFAULT
 * var secret by ksafe(0, protection = KSafeProtection.HARDWARE_ISOLATED) // SE/StrongBox
 * var setting by ksafe("default", protection = KSafeProtection.NONE)     // no encryption
 * ```
 */
enum class KSafeProtection {
    /**
     * No encryption — value is stored as plaintext.
     *
     * Equivalent to the old `encrypted = false`.
     */
    NONE,

    /**
     * Platform-default encryption.
     *
     * - **Android:** AES-256-GCM with keys in the TEE (Trusted Execution Environment).
     * - **iOS:** AES-256-GCM with keys in the Keychain.
     * - **JVM:** AES-256-GCM with software-backed keys.
     * - **WASM:** AES-256-GCM via WebCrypto.
     *
     * Equivalent to the old `encrypted = true`.
     */
    DEFAULT,

    /**
     * Hardware-isolated encryption using a dedicated security chip.
     *
     * - **Android:** StrongBox Keymaster (falls back to TEE if unavailable).
     * - **iOS:** Secure Enclave via envelope encryption (falls back to Keychain if unavailable).
     * - **JVM/WASM:** Falls back to [DEFAULT] (no hardware isolation available).
     */
    HARDWARE_ISOLATED
}
