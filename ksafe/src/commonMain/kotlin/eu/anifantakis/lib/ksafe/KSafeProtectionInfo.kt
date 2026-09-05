package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeProtectionNotes

/**
 * The encryption-key custody a [KSafe] instance is actually running with, including any
 * fallback negotiated at construction or later. Read it from [KSafe.protectionInfo]; for one
 * entry's key use [KSafe.getKeyInfo].
 */
data class KSafeProtectionInfo(
    /**
     * Strongest level this platform targets as its baseline. Never `HARDWARE_ISOLATED`: that level
     * is reached by per-write opt-in, not as a baseline.
     */
    val intendedLevel: KSafeProtectionLevel,

    /**
     * Level KSafe actually negotiated here. Differing from [intendedLevel] means protection is
     * weaker than intended, not that it fails — for that, use [isEncryptionOperational].
     */
    val effectiveLevel: KSafeProtectionLevel,

    /** Where keys actually live, in human-readable form. Safe to log, but never parse it. */
    val custody: String,

    /**
     * Stable lowercase_snake notes on the negotiation outcome, empty when nothing is noteworthy.
     * New codes may be added, so ignore unknown ones. `jvm_os_vault_degraded` and
     * `web_crypto_subtle_unavailable` mean every encrypted op fails; `jvm_os_vault_unavailable`,
     * `jvm_user_opted_out`, `android_strongbox_absent`, `apple_secure_enclave_absent`,
     * `apple_keychain_entitlement_missing` and `relaxed_default_uses_software_dek` are weaker
     * than intended but still operational.
     */
    val notes: List<String>,

    /** Published version of the linked KSafe artifact (mirrors [KSafe.VERSION]). */
    val kSafeVersion: String = KSAFE_VERSION,
) {
    /**
     * Whether encrypted reads and writes can succeed right now. `false` only for a [notes] code
     * that marks the engine non-operational; a weaker-but-working fallback still reads `true`.
     */
    val isEncryptionOperational: Boolean
        get() = notes.none { it in NON_OPERATIONAL_NOTES }

    companion object {
        private val NON_OPERATIONAL_NOTES = setOf(
            KSafeProtectionNotes.WEB_CRYPTO_SUBTLE_UNAVAILABLE,
            KSafeProtectionNotes.JVM_OS_VAULT_DEGRADED,
        )
    }
}
