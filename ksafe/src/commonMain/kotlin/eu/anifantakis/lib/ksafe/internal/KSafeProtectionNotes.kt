package eu.anifantakis.lib.ksafe.internal

/**
 * The `KSafeProtectionInfo.notes` vocabulary: a documented, stable string protocol between four
 * per-platform PRODUCERS and one consumer, `KSafeProtectionInfo.isEncryptionOperational`.
 *
 * Written once because a rename on one side alone is silent and wrong in the dangerous direction:
 * `isEncryptionOperational` matches produced notes against a set of non-operational codes, so a
 * producer whose code no longer matches makes it return `true` on a store where every encrypted
 * operation throws. There is no compile error and no runtime signal for that.
 *
 * The per-code semantics are documented on `KSafeProtectionInfo.notes`; this object owns only
 * their spelling.
 */
internal object KSafeProtectionNotes {
    const val JVM_OS_VAULT_UNAVAILABLE: String = "jvm_os_vault_unavailable"
    const val JVM_OS_VAULT_DEGRADED: String = "jvm_os_vault_degraded"
    const val JVM_USER_OPTED_OUT: String = "jvm_user_opted_out"
    const val ANDROID_STRONGBOX_ABSENT: String = "android_strongbox_absent"
    const val ANDROID_RELAXED_DEFAULT_USES_SOFTWARE_DEK: String = "relaxed_default_uses_software_dek"
    const val APPLE_SECURE_ENCLAVE_ABSENT: String = "apple_secure_enclave_absent"
    const val APPLE_KEYCHAIN_ENTITLEMENT_MISSING: String = "apple_keychain_entitlement_missing"
    const val WEB_CRYPTO_SUBTLE_UNAVAILABLE: String = "web_crypto_subtle_unavailable"
}
