package eu.anifantakis.lib.ksafe

/**
 * Universally-ordered scale describing **where the encryption key actually
 * lives** for a given [KSafe] instance, post-runtime-negotiation.
 *
 * Higher ordinal = harder for an attacker to recover the key. Comparable
 * across every platform with a single ordinal comparison:
 *
 * ```
 * check(ksafe.protectionInfo.effectiveLevel >= SANDBOX_PROTECTED)
 * ```
 *
 * **About data vs. key.** This scale describes the protection of the
 * encryption **key**, not the data. KSafe always encrypts payload data with
 * AES-256-GCM regardless of level. Even on the weakest rung ([SOFTWARE]) the
 * data on disk is still ciphertext — what varies across levels is how hard
 * it is for an attacker to recover the **key** that decrypts that ciphertext.
 *
 * Distinct from [KSafeKeyStorage], which is a *device capability* vocabulary
 * used by [KSafe.deviceKeyStorages]. This enum is about *negotiated runtime
 * custody* and is the value type used by [KSafeProtectionInfo].
 */
enum class KSafeProtectionLevel {

    /**
     * Key bytes are persisted **in a software file** with no sandbox
     * enforcement — only OS file permissions protect them. Any code that can
     * read the file as the same OS user recovers the key directly; backups,
     * copies, and stolen disks expose it intact.
     *
     * "Software" here refers to **key custody**, not data encryption — the
     * data on disk is still AES-256-GCM ciphertext. What's exposed is the
     * AES key bytes (Base64-encoded) in the same DataStore file.
     *
     * Reached only as the JVM fallback when no OS secret store is available
     * (no libsecret daemon, locked Keychain, JNA link failure, …) or when
     * the user explicitly opts out via `-Dksafe.jvm.keyVault=software` /
     * env `KSAFE_JVM_KEY_VAULT=software`.
     */
    SOFTWARE,

    /**
     * The key is protected by **software infrastructure provided by the
     * surrounding sandbox** — either a browser origin or an OS user account.
     * The raw key bytes are not readable from disk by another sandbox; the
     * runtime that owns the sandbox enforces the boundary.
     *
     * Producers:
     *  - **Web (wasmJs + js):** WebCrypto non-extractable `CryptoKey`
     *    persisted in IndexedDB. The browser enforces non-extractability and
     *    binds the key to the origin. The browser's own storage-encryption
     *    key is on every major desktop OS wrapped by the OS keyring
     *    (Chromium → DPAPI / Keychain / libsecret; Firefox similar), so a
     *    stolen disk without OS login is useless.
     *  - **JVM:** OS per-user secret store — Windows DPAPI (current-user),
     *    macOS login Keychain, or Linux Secret Service / libsecret. The OS
     *    enforces the user-account boundary; the same-OS-user code on the
     *    live session can still ask the OS for the key.
     *
     * Both are peer-strength: they protect against stolen-disk theft,
     * cross-sandbox access, and accidental backups; both are vulnerable to
     * code running inside the same sandbox.
     */
    SANDBOX_PROTECTED,

    /**
     * Held in on-chip secure hardware. Examples:
     *  - **Android:** Trusted Execution Environment (TEE / TrustZone), the
     *    default Keystore tier.
     *  - **Apple (iOS / macOS native):** Keychain backed by the platform's
     *    hardware key chain. On Apple Silicon and T2 Macs this involves the
     *    Secure Enclave Processor for key wrapping; on older Intel Macs
     *    without a T2 it falls back to software-backed Keychain.
     *
     * Distinct from [HARDWARE_ISOLATED], which is a *dedicated, physically
     * separate* security chip. Both are hardware-rooted; `HARDWARE_ISOLATED`
     * adds physical isolation and side-channel resistance against attacks
     * on the main SoC.
     */
    HARDWARE_BACKED,

    /**
     * Held in a dedicated, physically separate security chip. Examples:
     *  - **Android:** StrongBox Keymaster.
     *  - **Apple:** Secure Enclave envelope encryption (SE-resident EC P-256
     *    key wraps/unwraps the AES key via ECIES).
     *
     * Not an instance-level baseline on any platform today — reachable only
     * via per-write `KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)`.
     * Present on this scale so the ceiling isn't artificially capped and so
     * per-key reporting can use the same vocabulary in the future.
     */
    HARDWARE_ISOLATED,
}
