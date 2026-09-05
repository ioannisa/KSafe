package eu.anifantakis.lib.ksafe

/** Where key material can be stored; ordinal orders [SOFTWARE] < [HARDWARE_BACKED] < [HARDWARE_ISOLATED]. */
enum class KSafeKeyStorage {
    /** Software only — file system / localStorage (JVM, WASM). */
    SOFTWARE,

    /** On-chip hardware — Android TEE, iOS Keychain with Secure Element backing. */
    HARDWARE_BACKED,

    /** Dedicated security chip — Android StrongBox, iOS Secure Enclave. */
    HARDWARE_ISOLATED
}
