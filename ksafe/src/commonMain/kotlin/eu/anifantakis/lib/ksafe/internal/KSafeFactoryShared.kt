package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeEncryptedProtection
import eu.anifantakis.lib.ksafe.KSafeKeyStorage
import eu.anifantakis.lib.ksafe.KSafeProtectionLevel
import eu.anifantakis.lib.ksafe.KSafeWriteMode

/** Identity KSafe files its key material under in every OS key store; changing it orphans every
 *  key already minted. */
internal const val KSAFE_OS_STORE_IDENTITY: String = "eu.anifantakis.ksafe"

/** Key-slot prefix written by KSafe ≤ 2.0, still the live layout for the web and JVM stores.
 *  Frozen: it is a migration source and the reserved-key guard recognises it as internal. */
internal const val KSAFE_LEGACY_KEY_RECORD_PREFIX: String = "ksafe_key_"

/** Record-name prefix of every slot KSafe owns on disk. */
internal const val KSAFE_RESERVED_NAMESPACE_PREFIX: String = "__ksafe_"

/** Slot prefixes `getOrCreateSecret` reserves; the startup orphan sweep must never reap one. */
internal object KSafeSecretSlots {
    /** Slot for a `[A-Za-z0-9_]` key: the logical key verbatim. */
    const val PLAIN_PREFIX: String = "ksafe_secret_"

    /** Slot for any other key: the UTF-8 bytes of the key in lowercase hex. */
    const val HEX_PREFIX: String = "ksafe_secretx_"
}

private val STORE_FILE_NAME_PATTERN = Regex("[a-z][a-z0-9_]*")

internal fun requireValidStoreFileName(fileName: String?) {
    if (fileName != null && !fileName.matches(STORE_FILE_NAME_PATTERN)) {
        throw IllegalArgumentException(
            "File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores"
        )
    }
}

/** Segments KSafe reserves in the engine's alias plane; the alias writers and
 *  [KeySafeMetadataManager.requireWritableUserKey]'s guard both spell them from here. */
internal object KSafeReservedKeys {
    /** Shared master key for relaxed DEFAULT writes. */
    const val MASTER: String = "__ksafe_master__"

    /** Master key for writes requiring an unlocked device; collapses into [MASTER] where the platform has no device lock. */
    const val MASTER_LOCKED: String = "__ksafe_master_locked__"

    /** Marks a per-entry alias minted under the strict (`requireUnlockedDevice`) variant. */
    const val STRICT_VARIANT: String = "__ksafe_strict__"

    /** Marks a per-entry alias minted after a key rotation (generation ≥ 2). */
    const val ROTATED_VARIANT: String = "__ksafe_gen__"

    /** JVM vault deletion tombstone, appended to a per-entry vault alias. */
    const val VAULT_TOMBSTONE: String = "__ksafe_nsdel__"

    /** JVM software-fallback mint marker, appended to a per-entry vault alias. */
    const val VAULT_SOFTWARE_FALLBACK: String = "__ksafe_swfb__"
}

/** Dot-segments an engine alias is built from. The writers and the two readers that parse them
 *  back (the reserved-key guard, the Apple Keychain sweep) must agree, and a mismatch is silent. */
internal object KSafeAliasGrammar {
    /** Rotation-generation segment; appended only from generation 2 (generation 1 is the bare alias). */
    const val GENERATION_SEGMENT: String = ".g"

    /** Alias-fingerprint segment, carrying [KSafeCore.Companion.aliasFingerprint]'s output. */
    const val FINGERPRINT_SEGMENT: String = ".h"

    const val FINGERPRINT_HEX_LENGTH: Int = FNV1A_64_HEX_LENGTH

    val GENERATION_PATTERN: String = Regex.escape(GENERATION_SEGMENT) + """\d+"""

    val FINGERPRINT_PATTERN: String =
        Regex.escape(FINGERPRINT_SEGMENT) + """([0-9a-f]{$FINGERPRINT_HEX_LENGTH})"""
}

/** The two alias spellings KSafe files keys under. The platform factories and the Keychain sweep
 *  must derive byte-identical aliases, so both come from here. */
internal object KSafeAliasFormat {
    /** Dotted spelling for stores that namespace by service identity: `eu.anifantakis.ksafe[.fileName].key`. */
    fun dotted(fileName: String?, key: String): String =
        listOfNotNull(KSAFE_OS_STORE_IDENTITY, fileName, key).joinToString(".")

    /** The `eu.anifantakis.ksafe[.fileName]` root every [dotted] alias hangs off. */
    fun dottedBase(fileName: String?): String =
        listOfNotNull(KSAFE_OS_STORE_IDENTITY, fileName).joinToString(".")

    /** Colon spelling for stores already inside a KSafe-owned namespace: `[fileName:]key`. */
    fun colon(fileName: String?, key: String): String =
        fileName?.let { "$it:$key" } ?: key

    /** Master alias where the platform has a device-lock split: the two policies get distinct keys. */
    fun dottedMaster(fileName: String?, requireUnlockedDevice: Boolean): String =
        dotted(fileName, if (requireUnlockedDevice) KSafeReservedKeys.MASTER_LOCKED else KSafeReservedKeys.MASTER)

    /** Master alias where the platform has no device lock: both policies collapse onto one master. */
    fun colonMaster(fileName: String?): String = colon(fileName, KSafeReservedKeys.MASTER)
}

/** Where a key actually lives, as one answer behind both `getKeyInfo` vocabularies. */
internal enum class KSafeKeyTier {
    SOFTWARE,

    /** No [KSafeKeyStorage] spelling exists, so it projects to [KSafeKeyStorage.SOFTWARE]. */
    SANDBOX_PROTECTED,
    HARDWARE_BACKED,
    HARDWARE_ISOLATED,
}

internal fun KSafeKeyTier.asKeyStorage(): KSafeKeyStorage = when (this) {
    KSafeKeyTier.SOFTWARE, KSafeKeyTier.SANDBOX_PROTECTED -> KSafeKeyStorage.SOFTWARE
    KSafeKeyTier.HARDWARE_BACKED -> KSafeKeyStorage.HARDWARE_BACKED
    KSafeKeyTier.HARDWARE_ISOLATED -> KSafeKeyStorage.HARDWARE_ISOLATED
}

internal fun KSafeKeyTier.asProtectionLevel(): KSafeProtectionLevel = when (this) {
    KSafeKeyTier.SOFTWARE -> KSafeProtectionLevel.SOFTWARE
    KSafeKeyTier.SANDBOX_PROTECTED -> KSafeProtectionLevel.SANDBOX_PROTECTED
    KSafeKeyTier.HARDWARE_BACKED -> KSafeProtectionLevel.HARDWARE_BACKED
    KSafeKeyTier.HARDWARE_ISOLATED -> KSafeProtectionLevel.HARDWARE_ISOLATED
}

/** Applies the deprecated per-instance StrongBox / Secure Enclave opt-in: only an unqualified
 *  `DEFAULT` encrypted write is promoted, so a per-write protection always wins. */
@Suppress("DEPRECATION")
internal fun promoteDefaultToIsolated(mode: KSafeWriteMode, enabled: Boolean): KSafeWriteMode {
    if (!enabled) return mode
    if (mode !is KSafeWriteMode.Encrypted) return mode
    if (mode.protection != KSafeEncryptedProtection.DEFAULT) return mode
    return KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = mode.requireUnlockedDevice,
    )
}
