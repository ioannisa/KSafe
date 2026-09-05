package eu.anifantakis.lib.ksafe

/** Read-time protection tier reported by KSafe metadata APIs; for writes use [KSafeWriteMode]. */
enum class KSafeProtection {
    /** Platform-default AES-GCM; see [KSafeConfig.aesKeySize]. */
    DEFAULT,

    /**
     * Dedicated security chip where available — Android StrongBox, iOS Secure Enclave — falling back
     * to the TEE / Keychain when it is not, and to [DEFAULT] on JVM and WASM.
     */
    HARDWARE_ISOLATED
}
