package eu.anifantakis.lib.ksafe

/**
 * Internal/read-time protection tier used by KSafe metadata and key info APIs.
 *
 * For write calls, use [KSafeWriteMode]:
 * - [KSafeWriteMode.Plain]
 * - [KSafeWriteMode.Encrypted]
 */
enum class KSafeProtection {
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
