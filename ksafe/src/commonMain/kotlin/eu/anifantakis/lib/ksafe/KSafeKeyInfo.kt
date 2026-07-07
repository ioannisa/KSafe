package eu.anifantakis.lib.ksafe

/**
 * Protection and storage details of a specific key.
 *
 * @property protection The tier the write asked for, or `null` for plaintext
 *   entries ([KSafeWriteMode.Plain]).
 * @property storage Where key material resides in the legacy three-value
 *   [KSafeKeyStorage] vocabulary; kept for binary compatibility, prefer [level].
 * @property level Where key material resides on the universally-ordered
 *   [KSafeProtectionLevel] scale — more granular than [storage] on JVM and Web
 *   (distinguishes [KSafeProtectionLevel.SANDBOX_PROTECTED] from
 *   [KSafeProtectionLevel.SOFTWARE]), 1:1 on Android / Apple.
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
