package eu.anifantakis.lib.ksafe

/**
 * Explicit write mode for KSafe put operations.
 *
 * This makes invalid combinations unrepresentable:
 * - Plain writes cannot set unlock policy
 * - Unlock policy is only available for encrypted writes
 */
sealed interface KSafeWriteMode {
    data object Plain : KSafeWriteMode

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
