package eu.anifantakis.lib.ksafe

/**
 * Where the encryption key lives after runtime negotiation; higher ordinal = harder to recover,
 * comparable across platforms. Describes the key, not the data — the payload is always AES-GCM.
 * Reported per instance by [KSafeProtectionInfo] and per entry by [KSafeKeyInfo.level].
 */
enum class KSafeProtectionLevel {

    /**
     * Key bytes in a plain file, guarded only by OS file permissions — the JVM fallback when no OS
     * secret store is available. On web it also marks a missing `crypto.subtle`, where every
     * encrypted op fails; only the `web_crypto_subtle_unavailable` note tells the two apart.
     * Also what [KSafeKeyInfo.level] reports for a plaintext entry on every platform.
     */
    SOFTWARE,

    /**
     * Key protected by the surrounding sandbox: a browser origin (non-extractable WebCrypto key in
     * IndexedDB) or an OS user account (Windows DPAPI, macOS login Keychain, libsecret).
     */
    SANDBOX_PROTECTED,

    /** Held in on-chip secure hardware: the Android TEE, or a hardware-backed Apple Keychain. */
    HARDWARE_BACKED,

    /**
     * Held in a physically separate security chip — Android StrongBox or the Apple Secure Enclave.
     * Reachable only per write, via `KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)`.
     */
    HARDWARE_ISOLATED,
}
