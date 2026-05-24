package eu.anifantakis.lib.ksafe

/**
 * Describes the protection and storage details of a specific key.
 *
 * @property protection The encrypted protection tier the *write* asked for
 *   ([KSafeProtection.DEFAULT] / [KSafeProtection.HARDWARE_ISOLATED]), or
 *   `null` for plaintext entries (`KSafeWriteMode.Plain`).
 * @property storage Where the encryption key material actually resides on
 *   this device, in the **legacy three-value capability vocabulary**
 *   ([KSafeKeyStorage]). Kept for binary compatibility with KSafe ≤ 2.0
 *   consumers; prefer [level].
 * @property level Where the encryption key actually resides on the new
 *   universally-ordered protection scale ([KSafeProtectionLevel]). More
 *   granular than [storage] on JVM (distinguishes
 *   [KSafeProtectionLevel.SANDBOX_PROTECTED] OS-vault keys from
 *   [KSafeProtectionLevel.SOFTWARE] plaintext-in-file fallback) and on Web
 *   (reports [KSafeProtectionLevel.SANDBOX_PROTECTED] for the browser-origin
 *   non-extractable key, where `storage` could only say `SOFTWARE`).
 *   Match-up with [storage] on Android / Apple is 1:1.
 */
data class KSafeKeyInfo(
    val protection: KSafeProtection?,
    @Deprecated(
        message = "Use level (KSafeProtectionLevel) — a universally-ordered scale that " +
            "additionally distinguishes JVM OS-vault keys (SANDBOX_PROTECTED) from " +
            "the plaintext-in-file fallback (SOFTWARE), and Web browser-origin keys " +
            "(SANDBOX_PROTECTED) from raw software (SOFTWARE).",
        replaceWith = ReplaceWith("level"),
    )
    val storage: KSafeKeyStorage,
    val level: KSafeProtectionLevel,
)
