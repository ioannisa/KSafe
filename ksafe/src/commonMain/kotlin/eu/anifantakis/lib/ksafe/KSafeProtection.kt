package eu.anifantakis.lib.ksafe

/**
 * Read-time protection tier reported by KSafe metadata / key-info APIs. For
 * writes, use [KSafeWriteMode] ([KSafeWriteMode.Plain] / [KSafeWriteMode.Encrypted]).
 */
enum class KSafeProtection {
    /** Platform-default AES-256-GCM (Android TEE, iOS Keychain, JVM software, WASM WebCrypto). */
    DEFAULT,

    /**
     * Hardware-isolated encryption via a dedicated security chip: Android StrongBox
     * (falls back to TEE), iOS Secure Enclave (falls back to Keychain); JVM/WASM fall
     * back to [DEFAULT].
     */
    HARDWARE_ISOLATED
}
