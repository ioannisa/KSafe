package eu.anifantakis.lib.ksafe.internal

/**
 * Spelling of the `KSafeProtectionInfo.notes` codes. `isEncryptionOperational` matches produced
 * notes against these strings, so renaming one side alone silently reports a broken store as healthy.
 */
internal object KSafeProtectionNotes {
    const val JVM_OS_VAULT_UNAVAILABLE: String = "jvm_os_vault_unavailable"
    const val JVM_OS_VAULT_DEGRADED: String = "jvm_os_vault_degraded"
    const val JVM_USER_OPTED_OUT: String = "jvm_user_opted_out"
    const val ANDROID_STRONGBOX_ABSENT: String = "android_strongbox_absent"
    const val ANDROID_RELAXED_DEFAULT_USES_SOFTWARE_DEK: String = "relaxed_default_uses_software_dek"
    /** API 28..34 without a secure lock screen: strict keys are minted without `setUnlockedDeviceRequired`.
     *  Reported while the next mint would relax or the master in use was minted that way; only a new
     *  key generation clears it, and rotation is opt-in. */
    const val ANDROID_LOCK_SCREEN_ABSENT: String = "android_lock_screen_absent"
    const val APPLE_SECURE_ENCLAVE_ABSENT: String = "apple_secure_enclave_absent"
    const val APPLE_KEYCHAIN_ENTITLEMENT_MISSING: String = "apple_keychain_entitlement_missing"
    const val WEB_CRYPTO_SUBTLE_UNAVAILABLE: String = "web_crypto_subtle_unavailable"
}
