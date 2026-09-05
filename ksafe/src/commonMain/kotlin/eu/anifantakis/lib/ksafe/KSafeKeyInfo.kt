package eu.anifantakis.lib.ksafe

/**
 * Protection and storage details of a specific key.
 *
 * @property protection Tier the write asked for, or `null` for plaintext entries.
 * @property storage Legacy three-value view of where key material resides; prefer [level].
 * @property level Where key material resides on the ordered [KSafeProtectionLevel] scale; more
 *   granular than [storage] on JVM and Web, and checked against the live key on Apple/Android 31+.
 * @property keyGeneration Generation that decrypts this entry; 1 until [KSafe.rotateKeys] moves it.
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
    val keyGeneration: Int = 1,
)
