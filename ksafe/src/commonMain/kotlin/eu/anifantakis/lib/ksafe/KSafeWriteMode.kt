package eu.anifantakis.lib.ksafe

/** Write mode for KSafe put operations; only encrypted writes can set an unlock policy. */
sealed interface KSafeWriteMode {
    data object Plain : KSafeWriteMode

    /**
     * @property requireUnlockedDevice Keeps the entry's key usable only while the device is
     *   unlocked. Enforced on Android and Apple only; JVM and web store an ordinary encrypted
     *   entry instead, so treat it as hardening, not a portable guarantee. On Android 28-34
     *   removing the lock screen can silently delete such keys (the value self-heals to its
     *   default), and key use can fail while no secure lock screen is configured.
     */
    data class Encrypted(
        val protection: KSafeEncryptedProtection = KSafeEncryptedProtection.DEFAULT,
        val requireUnlockedDevice: Boolean = false
    ) : KSafeWriteMode
}

/** Encrypted-only protection levels. */
enum class KSafeEncryptedProtection {
    DEFAULT,
    HARDWARE_ISOLATED
}

@PublishedApi
internal fun KSafeWriteMode.toProtection(): KSafeProtection? {
    return when (this) {
        KSafeWriteMode.Plain -> null
        is KSafeWriteMode.Encrypted -> when (protection) {
            KSafeEncryptedProtection.DEFAULT -> KSafeProtection.DEFAULT
            KSafeEncryptedProtection.HARDWARE_ISOLATED -> KSafeProtection.HARDWARE_ISOLATED
        }
    }
}
