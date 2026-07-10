package eu.anifantakis.lib.ksafe

/**
 * Instance-level diagnostic describing the encryption-key custody this [KSafe]
 * is actually running with, including any runtime fallback during construction.
 *
 * Complements [KSafe.deviceKeyStorages] (device capability probe) and
 * [KSafe.getKeyInfo] (per-key storage); this is the third surface — what the
 * engine is running at right now, for this process.
 */
data class KSafeProtectionInfo(
    /**
     * Strongest level this platform's engine targets as its baseline at
     * construction time. Equals [effectiveLevel] unless runtime negotiation
     * fell back (JVM only today). Never `HARDWARE_ISOLATED` — that is reached
     * via per-write opt-in, not as a baseline.
     */
    val intendedLevel: KSafeProtectionLevel,

    /** Level KSafe actually negotiated for this instance; the value to gate on. */
    val effectiveLevel: KSafeProtectionLevel,

    /**
     * Human-readable description of where keys actually live. Safe to
     * log/display, but never parse it — the wording is diagnostic, not contract.
     */
    val custody: String,

    /**
     * Stable lowercase_snake notes on the negotiation outcome; empty when
     * nothing noteworthy happened. New codes may be added, so ignore unknown
     * ones rather than rejecting them. Defined codes:
     *  - `"jvm_os_vault_unavailable"` — JVM: OS-vault self-test failed (no libsecret
     *    daemon, locked Keychain, JNA link error, …); keys fall back to software.
     *  - `"jvm_user_opted_out"` — JVM: `-Dksafe.jvm.keyVault=software` (or env
     *    `KSAFE_JVM_KEY_VAULT=software`) forced the software vault.
     *  - `"android_strongbox_absent"` — Android: device lacks StrongBox.
     *  - `"apple_secure_enclave_absent"` — Apple: device lacks a Secure Enclave.
     *  - `"apple_keychain_entitlement_missing"` — iOS Simulator: the Keychain rejected
     *    the process (`errSecMissingEntitlement`, no signing team / Keychain Sharing
     *    capability); keys fall back to a sandbox file store. Never emitted on device.
     */
    val notes: List<String>,

    /**
     * Published version of the linked KSafe artifact (mirrors [KSafe.VERSION]),
     * so a diagnostic snapshot records which build is actually linked.
     */
    val kSafeVersion: String = KSAFE_VERSION,
)
