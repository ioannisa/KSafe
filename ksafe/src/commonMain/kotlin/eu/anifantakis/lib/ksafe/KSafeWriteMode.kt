package eu.anifantakis.lib.ksafe

/**
 * Explicit write mode for KSafe put operations, making invalid combinations
 * unrepresentable — only encrypted writes can set an unlock policy.
 */
sealed interface KSafeWriteMode {
    data object Plain : KSafeWriteMode

    /**
     * @property requireUnlockedDevice When `true`, this entry's key is only usable while the
     *   device is unlocked (Android API 28+ / iOS Keychain accessibility).
     *
     *   **Enforced on Android and Apple only.** JVM Desktop has no device-lock concept to key
     *   against, and browsers have neither that nor a synchronous decrypt — a strict entry
     *   there would be write-only, so the web factory drops the flag and keeps the value
     *   readable instead. On both, the entry is stored as an ordinary encrypted one and the
     *   request is silently satisfied at the weaker guarantee: shared code asking for it does
     *   not fail, it simply does not get it. Treat it as a hardening on the platforms that
     *   have a lock screen, never as a portable guarantee — if an entry must be unreadable
     *   while the machine is locked, gate it in your own code too.
     *
     *   Android caveat: before Android 15 (API 35) the platform's
     *   `setUnlockedDeviceRequired(true)` had documented bugs on API 28-34 — removing the
     *   lock screen can silently delete such keys (the value then self-heals to its default
     *   via the missing-key sweep), and key generation/use can fail while no secure lock
     *   screen is configured.
     */
    data class Encrypted(
        val protection: KSafeEncryptedProtection = KSafeEncryptedProtection.DEFAULT,
        val requireUnlockedDevice: Boolean = false
    ) : KSafeWriteMode
}

/**
 * Encrypted-only protection levels.
 */
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
