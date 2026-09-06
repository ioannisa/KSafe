package eu.anifantakis.lib.ksafe

/** Write mode for a `put`; [KSafe.defaultWriteMode] applies when a call passes none. Only
 *  encrypted writes can set an unlock policy. */
sealed interface KSafeWriteMode {
    /** Stores the value unencrypted; no key store is involved. */
    data object Plain : KSafeWriteMode

    /**
     * Encrypts the value under the instance's key.
     *
     * @property protection Key tier to write under; [KSafeEncryptedProtection.HARDWARE_ISOLATED]
     *   asks for StrongBox / Secure Enclave and falls back to the platform default where absent.
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

/** Protection tiers an encrypted write can ask for; reads report the tier as [KSafeProtection]. */
enum class KSafeEncryptedProtection {
    /** The platform's default key store: Android Keystore, Apple Keychain, OS vault or
     *  browser-origin key on JVM and web. */
    DEFAULT,

    /** A dedicated security chip — Android StrongBox, Apple Secure Enclave — when present;
     *  otherwise the same store as [DEFAULT]. */
    HARDWARE_ISOLATED
}

/** The [KSafeProtection] this mode records on the entry, or `null` for [KSafeWriteMode.Plain]. */
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
