package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeProtectionNotes

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
     * fell back — today the JVM software-vault fallback, or web in a non-secure
     * context (no `crypto.subtle`). Never `HARDWARE_ISOLATED` — that is reached
     * via per-write opt-in, not as a baseline.
     */
    val intendedLevel: KSafeProtectionLevel,

    /**
     * Level KSafe actually negotiated for this instance. Two different questions,
     * two different gates — don't conflate them:
     *  - **"Is protection at its intended strength?"** → `effectiveLevel != intendedLevel`
     *    (or an ordinal comparison). A divergence means a runtime fallback occurred, but
     *    encryption may still be fully OPERATIONAL: a JVM software-vault fallback and an
     *    iOS-Simulator sandbox key store both report [KSafeProtectionLevel.SOFTWARE] and
     *    encrypt/decrypt normally.
     *  - **"Will encrypted reads/writes actually succeed?"** → check the relevant [notes]
     *    code, NOT the level. Non-operational states are web in a non-secure context
     *    (`web_crypto_subtle_unavailable`) and a JVM whose OS vault exists but is unreachable
     *    (`jvm_os_vault_degraded`) — both make every encrypted op fail. Gating on
     *    `effectiveLevel != intendedLevel` would instead wrongly reject the operational
     *    JVM-software / iOS-Simulator fallbacks above, which run at [SOFTWARE] yet encrypt fine.
     */
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
     *  - `"jvm_os_vault_unavailable"` — JVM: no OS secret store is reachable on this host
     *    (no libsecret daemon, unsupported OS); keys fall back to software. Weaker than
     *    intended but still fully OPERATIONAL.
     *  - `"jvm_os_vault_degraded"` — JVM: an OS secret store EXISTS but failed its self-test
     *    (locked Keychain/keyring, headless launch). To avoid overwriting the
     *    real OS key on a later healthy launch, KSafe refuses to mint keys, so encrypted
     *    reads/writes FAIL until it is reachable — NON-operational ([isEncryptionOperational]
     *    is `false`). Retry once the store is unlocked, or set `-Dksafe.jvm.keyVault=software`.
     *  - `"jvm_user_opted_out"` — JVM: `-Dksafe.jvm.keyVault=software` (or env
     *    `KSAFE_JVM_KEY_VAULT=software`) forced the software vault.
     *  - `"android_strongbox_absent"` — Android: device lacks StrongBox.
     *  - `"relaxed_default_uses_software_dek"` — Android, always present: relaxed `DEFAULT`
     *    values are encrypted with a data key that the Keystore master key wraps, and whose
     *    unwrapped bytes live in process memory after first use — the trade that makes ordinary
     *    encrypted reads pure-CPU instead of a hardware round-trip per read. `HARDWARE_ISOLATED`
     *    entries and strict masters never take this path and keep their keys inside the TEE.
     *  - `"apple_secure_enclave_absent"` — Apple: device lacks a Secure Enclave.
     *  - `"apple_keychain_entitlement_missing"` — iOS Simulator: the Keychain rejected
     *    the process (`errSecMissingEntitlement`, no signing team / Keychain Sharing
     *    capability); keys fall back to a sandbox file store. Never emitted on device.
     *  - `"web_crypto_subtle_unavailable"` — Web: the page is not a secure context, so
     *    `crypto.subtle` (WebCrypto) is absent and every encrypted read/write fails;
     *    [effectiveLevel] drops to [KSafeProtectionLevel.SOFTWARE]. Serve over HTTPS or
     *    from a localhost origin to restore encryption.
     */
    val notes: List<String>,

    /**
     * Published version of the linked KSafe artifact (mirrors [KSafe.VERSION]),
     * so a diagnostic snapshot records which build is actually linked.
     */
    val kSafeVersion: String = KSAFE_VERSION,
) {
    /**
     * Whether encrypted reads/writes can actually succeed on this instance right now —
     * the cross-platform "will my encrypted write persist?" preflight.
     *
     * `false` only when a [notes] code marks the engine non-operational: web in a non-secure
     * context (`web_crypto_subtle_unavailable`, no `crypto.subtle`), or a JVM whose OS secret
     * store exists but is unreachable (`jvm_os_vault_degraded`, e.g. a locked Keychain/keyring)
     * so KSafe refuses to mint keys — both make every encrypted op fail. Distinct from
     * protection *strength*: a JVM software-vault fallback (no OS store at all) and an
     * iOS-Simulator sandbox key store are weaker than intended but still fully operational, so
     * this stays `true` there. For the strength question compare [effectiveLevel] against
     * [intendedLevel] instead.
     */
    val isEncryptionOperational: Boolean
        get() = notes.none { it in NON_OPERATIONAL_NOTES }

    companion object {
        /** [notes] codes that mean encrypted ops fail outright, not merely run weaker. */
        private val NON_OPERATIONAL_NOTES = setOf(
            KSafeProtectionNotes.WEB_CRYPTO_SUBTLE_UNAVAILABLE,
            KSafeProtectionNotes.JVM_OS_VAULT_DEGRADED,
        )
    }
}
