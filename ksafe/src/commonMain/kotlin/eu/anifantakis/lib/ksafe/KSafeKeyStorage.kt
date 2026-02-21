package eu.anifantakis.lib.ksafe

/**
 * Describes the hardware protection level used for cryptographic key storage.
 *
 * Enum ordinal provides natural ordering: [SOFTWARE] < [HARDWARE_BACKED] < [HARDWARE_ISOLATED].
 * Use `deviceKeyStorages.max()` to get the highest level available on the current device.
 */
enum class KSafeKeyStorage {
    /**
     * Keys are stored in software only (file system / localStorage).
     *
     * **Platforms:** JVM, WASM.
     */
    SOFTWARE,

    /**
     * Keys are stored in on-chip hardware (TEE / Keychain).
     *
     * **Platforms:** Android (Trusted Execution Environment), iOS (Keychain with Secure Element backing).
     */
    HARDWARE_BACKED,

    /**
     * Keys are stored in a dedicated, physically separate security chip.
     *
     * **Platforms:** Android (StrongBox), iOS (Secure Enclave).
     */
    HARDWARE_ISOLATED
}
