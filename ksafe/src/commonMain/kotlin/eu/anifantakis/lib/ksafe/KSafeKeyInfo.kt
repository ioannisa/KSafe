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
 *   [KSafeProtectionLevel.SOFTWARE]), 1:1 on Android / Apple. On Apple this is
 *   verified against the live Keychain custody of the entry's key (falling back
 *   to capability inference when the key cannot be classified). On Android
 *   API 31+ it is verified against the Keystore key's actual security level —
 *   a silent StrongBox-to-TEE fallback reports
 *   [KSafeProtectionLevel.HARDWARE_BACKED]; API 28-30 cannot distinguish
 *   StrongBox from TEE, so those keep the requested-tier-plus-StrongBox-capability
 *   inference (as does any key the probe cannot classify).
 * @property keyGeneration Which key generation decrypts this entry: 1 for a
 *   never-rotated entry, higher after [KSafe.rotateKeys]. An entry still behind
 *   the store's latest generation is picked up by the next rotation. Always 1
 *   for plaintext entries (they have no key).
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
