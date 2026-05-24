package eu.anifantakis.lib.ksafe

/**
 * Instance-level diagnostic describing the encryption-key custody this
 * [KSafe] is actually running with — including any runtime fallback that
 * happened during construction.
 *
 * Complements the two pre-existing surfaces:
 *  - [KSafe.deviceKeyStorages] — *what the device could do* (capability probe).
 *  - [KSafe.getKeyInfo] — *what one specific key got stored with* (per-key).
 *
 * `protectionInfo` is the missing third surface: *what the engine is running
 * at right now, for this process*. Read it once at startup to gate, log, or
 * surface a UI badge:
 *
 * ```
 * val info = ksafe.protectionInfo
 *
 * // Refuse the software-only key custody fallback
 * check(info.effectiveLevel > KSafeProtectionLevel.SOFTWARE)
 *
 * // Require at least sandbox-mediated protection (Web origin or OS user account)
 * check(info.effectiveLevel >= KSafeProtectionLevel.SANDBOX_PROTECTED)
 *
 * // Require on-chip hardware custody
 * check(info.effectiveLevel >= KSafeProtectionLevel.HARDWARE_BACKED)
 *
 * // "Did we get less than we aimed for?"
 * check(info.effectiveLevel >= info.intendedLevel)
 *
 * // Telemetry — every field is a stable, low-cardinality identifier
 * analytics.log(
 *     "ksafe_protection",
 *     "level"    to info.effectiveLevel.name,
 *     "custody"  to info.custody,
 *     "notes"    to info.notes.joinToString(","),
 * )
 * ```
 */
data class KSafeProtectionInfo(
    /**
     * Strongest level this platform's engine targets as its **baseline** at
     * construction time. Equal to [effectiveLevel] on the happy path; higher
     * than [effectiveLevel] when runtime negotiation fell back (today: JVM
     * only, when the OS vault is unavailable or the user opted out).
     *
     * `HARDWARE_ISOLATED` is never an `intendedLevel` value — it's reached
     * only via per-write opt-in, not as a baseline.
     */
    val intendedLevel: KSafeProtectionLevel,

    /**
     * Level KSafe actually negotiated for this instance. The value to gate
     * on for "is my protection good enough?".
     */
    val effectiveLevel: KSafeProtectionLevel,

    /**
     * Human-readable description of where keys actually live. Stable enough
     * to log/display, but **never parse it** — the wording is part of the
     * diagnostic, not the contract.
     *
     * Examples:
     *  - `"Android Keystore (TEE)"`
     *  - `"Apple Keychain (Secure Enclave available per-write)"`
     *  - `"Windows DPAPI (current-user)"`
     *  - `"macOS Keychain (login)"`
     *  - `"Linux Secret Service (libsecret)"`
     *  - `"DataStore file (plaintext fallback — no OS protection)"`
     *  - `"WebCrypto non-extractable key in IndexedDB"`
     */
    val custody: String,

    /**
     * Stable lowercase_snake notes on the negotiation outcome. Empty when
     * nothing noteworthy happened.
     *
     * Defined codes:
     *  - `"jvm_os_vault_unavailable"` — JVM: OS-vault self-test failed
     *    (no libsecret daemon, locked Keychain, JNA link error, …).
     *  - `"jvm_user_opted_out"` — JVM: `-Dksafe.jvm.keyVault=software`
     *    or env `KSAFE_JVM_KEY_VAULT=software` set.
     *  - `"android_strongbox_absent"` — Android: device lacks StrongBox.
     *    Informational at instance level; only meaningful for per-write
     *    `HARDWARE_ISOLATED`.
     *  - `"apple_secure_enclave_absent"` — Apple: device lacks SE
     *    (simulator, pre-T2 Intel Mac). Informational at instance level.
     *
     * Codes are stable across minor versions; new codes may be added.
     * Consumers should ignore unknown codes rather than reject them.
     */
    val notes: List<String>,
)
