package eu.anifantakis.lib.ksafe

/**
 * Coarse scale of where key material can live, ordered [SOFTWARE] < [HARDWARE_BACKED] <
 * [HARDWARE_ISOLATED]. Used by [KSafe.deviceKeyStorages]; for what a key actually got, prefer
 * [KSafeProtectionLevel], which also separates OS-vault and browser-origin custody from raw files.
 */
enum class KSafeKeyStorage {
    /**
     * No secure hardware: JVM (OS secret store or key file) and Web (WebCrypto key in IndexedDB).
     * [KSafeProtectionLevel.SANDBOX_PROTECTED] keys also report this value.
     */
    SOFTWARE,

    /** On-chip secure hardware — the Android TEE, or the Apple Keychain. */
    HARDWARE_BACKED,

    /** Dedicated security chip — Android StrongBox, Apple Secure Enclave. */
    HARDWARE_ISOLATED
}
