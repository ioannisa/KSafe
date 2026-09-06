package eu.anifantakis.lib.ksafe

/** Tier an encrypted entry was written under, as reported by [KSafeKeyInfo.protection]; choose
 *  it at write time through [KSafeWriteMode.Encrypted]. */
enum class KSafeProtection {
    /** The platform's default key store: Android Keystore, Apple Keychain, OS vault or
     *  browser-origin key on JVM and web. AES-GCM with [KSafeConfig.aesKeySize]. */
    DEFAULT,

    /**
     * Dedicated security chip where available — Android StrongBox, iOS Secure Enclave — falling back
     * to the TEE / Keychain when it is not, and to [DEFAULT] on JVM and WASM.
     */
    HARDWARE_ISOLATED
}
