package eu.anifantakis.lib.ksafe

/**
 * Describes the protection and storage details of a specific key.
 *
 * @property protection The protection tier used when this key was stored.
 * @property storage Where the encryption key material actually resides on this device.
 */
data class KSafeKeyInfo(
    val protection: KSafeProtection,
    val storage: KSafeKeyStorage
)
