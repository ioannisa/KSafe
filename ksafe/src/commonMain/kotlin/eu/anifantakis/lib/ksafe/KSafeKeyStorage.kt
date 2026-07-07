package eu.anifantakis.lib.ksafe

/**
 * Device-capability vocabulary for where cryptographic key material can be stored.
 * Ordinal orders [SOFTWARE] < [HARDWARE_BACKED] < [HARDWARE_ISOLATED];
 * `deviceKeyStorages.max()` gives the highest level available on the device.
 */
enum class KSafeKeyStorage {
    /** Software only — file system / localStorage (JVM, WASM). */
    SOFTWARE,

    /** On-chip hardware — Android TEE, iOS Keychain with Secure Element backing. */
    HARDWARE_BACKED,

    /** Dedicated, physically separate security chip — Android StrongBox, iOS Secure Enclave. */
    HARDWARE_ISOLATED
}
