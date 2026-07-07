package eu.anifantakis.lib.ksafe

/**
 * Universally-ordered scale describing where the encryption key actually lives
 * for a [KSafe] instance after runtime negotiation; higher ordinal = harder for
 * an attacker to recover the key, comparable across every platform by ordinal.
 *
 * Describes the key's protection, not the data: payload is always AES-256-GCM
 * ciphertext regardless of level — what varies is how hard the key is to recover.
 *
 * Distinct from [KSafeKeyStorage] (device-capability vocabulary used by
 * [KSafe.deviceKeyStorages]); this is negotiated runtime custody and the value
 * type of [KSafeProtectionInfo].
 */
enum class KSafeProtectionLevel {

    /**
     * Key bytes persisted in a software file with no sandbox enforcement — only
     * OS file permissions protect them; same-OS-user code, backups, copies, and
     * stolen disks expose the AES key intact. The JVM fallback when no OS secret
     * store is available or the user opts out via `-Dksafe.jvm.keyVault=software`
     * / env `KSAFE_JVM_KEY_VAULT=software`.
     */
    SOFTWARE,

    /**
     * Key protected by the surrounding sandbox — a browser origin or an OS user
     * account — whose runtime enforces the boundary; raw key bytes aren't
     * readable from disk by another sandbox, but same-sandbox code still can.
     *
     * Producers: Web (WebCrypto non-extractable key in IndexedDB, bound to the
     * origin) and JVM (OS per-user secret store — Windows DPAPI, macOS login
     * Keychain, or Linux Secret Service / libsecret).
     */
    SANDBOX_PROTECTED,

    /**
     * Held in on-chip secure hardware: Android TEE (TrustZone, the default
     * Keystore tier), or Apple Keychain hardware-backed (Secure Enclave wrapping
     * on Apple Silicon / T2, software-backed on older Intel Macs). Distinct from
     * [HARDWARE_ISOLATED], which adds a physically separate chip.
     */
    HARDWARE_BACKED,

    /**
     * Held in a dedicated, physically separate security chip: Android StrongBox,
     * or Apple Secure Enclave envelope encryption. Not an instance-level baseline
     * on any platform today — reachable only via per-write
     * `KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)`.
     */
    HARDWARE_ISOLATED,
}
