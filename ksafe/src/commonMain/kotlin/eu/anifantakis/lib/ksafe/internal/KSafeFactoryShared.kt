package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeEncryptedProtection
import eu.anifantakis.lib.ksafe.KSafeKeyStorage
import eu.anifantakis.lib.ksafe.KSafeProtectionLevel
import eu.anifantakis.lib.ksafe.KSafeWriteMode

/**
 * The identity KSafe files its key material under in every OS key store: the Android Keystore
 * alias prefix, the Apple Keychain service and key prefix, the macOS Keychain service, the Linux
 * Secret Service schema. Changing it orphans every key already minted.
 */
internal const val KSAFE_OS_STORE_IDENTITY: String = "eu.anifantakis.ksafe"

/**
 * Record-name prefix of the in-store key slots written by KSafe ≤ 2.0 (still the live layout for
 * the web engine's IndexedDB names and the JVM DataStore vault). Frozen: it is a migration source,
 * and the reserved-key guard recognises it as internal.
 */
internal const val KSAFE_LEGACY_KEY_RECORD_PREFIX: String = "ksafe_key_"

/**
 * Record-name prefix of every slot KSafe owns on disk. Both the reserved-key guard that keeps
 * user keys out of it and the web migration gate that decides which localStorage entries move
 * are matching the SAME namespace, so they spell it from here.
 */
internal const val KSAFE_RESERVED_NAMESPACE_PREFIX: String = "__ksafe_"

/**
 * Record-name prefixes of the slots `getOrCreateSecret` reserves. The writer and the startup orphan
 * sweep that must never reap one spell them from here.
 */
internal object KSafeSecretSlots {
    /** Slot for a `[A-Za-z0-9_]` key: the logical key verbatim. */
    const val PLAIN_PREFIX: String = "ksafe_secret_"

    /** Slot for any other key: the UTF-8 bytes of the key in lowercase hex. */
    const val HEX_PREFIX: String = "ksafe_secretx_"
}

private val STORE_FILE_NAME_PATTERN = Regex("[a-z][a-z0-9_]*")

/** Validates a factory `fileName`; null (the default store) is always accepted. */
internal fun requireValidStoreFileName(fileName: String?) {
    if (fileName != null && !fileName.matches(STORE_FILE_NAME_PATTERN)) {
        throw IllegalArgumentException(
            "File name must start with a lowercase letter and contain only lowercase letters, digits, or underscores"
        )
    }
}

/**
 * Segments KSafe reserves inside the engine's alias plane. Declared once so the code that WRITES
 * an alias and the guard that keeps user keys off that alias
 * ([KeySafeMetadataManager.requireWritableUserKey], whose pattern is built from these) can never
 * drift apart — every reservation miss so far came from re-typing one of these literals.
 */
internal object KSafeReservedKeys {
    /** Shared master key for relaxed DEFAULT writes; `__`-fenced so it can't collide with a user key. */
    const val MASTER: String = "__ksafe_master__"

    /** Master key for writes that require an unlocked device; collapses into [MASTER] where the platform has no device lock. */
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

/**
 * The dot-segments an engine alias is built from, beyond the [KSafeReservedKeys] sentinels.
 * Declared here for the same reason those are: the alias WRITERS
 * ([KSafeCore.Companion.aliasWithGeneration] and the two per-entry spellings) and the two
 * independent READERS that parse them back ([KeySafeMetadataManager.requireWritableUserKey]'s
 * guard, the Apple Keychain orphan sweep) must agree on the grammar exactly. Re-spelling a
 * segment or widening the fingerprint on only one side makes the reader match nothing, which
 * is silent in both directions — orphaned Secure Enclave keys are never reaped, and a
 * colliding user key stops being barred.
 */
internal object KSafeAliasGrammar {
    /** Rotation-generation segment; appended only from generation 2 (generation 1 is the bare alias). */
    const val GENERATION_SEGMENT: String = ".g"

    /** Alias-fingerprint segment, carrying [KSafeCore.Companion.aliasFingerprint]'s output. */
    const val FINGERPRINT_SEGMENT: String = ".h"

    /** Width of a fingerprint: it IS an FNV-1a-64 digest, so the readers' width follows the hash's. */
    const val FINGERPRINT_HEX_LENGTH: Int = FNV1A_64_HEX_LENGTH

    /** [GENERATION_SEGMENT] plus its decimal generation, as a regex fragment. */
    val GENERATION_PATTERN: String = Regex.escape(GENERATION_SEGMENT) + """\d+"""

    /** [FINGERPRINT_SEGMENT] plus its hex digits (captured), as a regex fragment. */
    val FINGERPRINT_PATTERN: String =
        Regex.escape(FINGERPRINT_SEGMENT) + """([0-9a-f]{$FINGERPRINT_HEX_LENGTH})"""
}

/**
 * The two alias spellings KSafe files keys under. Written once because the factory, the fallback
 * migration and the Keychain orphan sweep must derive byte-identical aliases from the same
 * `fileName` — a re-typed formula in any one of them silently orphans key material.
 */
internal object KSafeAliasFormat {
    /**
     * Dotted spelling for the OS key stores that namespace by service identity (Android Keystore
     * aliases, Apple Keychain accounts): `eu.anifantakis.ksafe[.fileName].key`.
     */
    fun dotted(fileName: String?, key: String): String =
        listOfNotNull(KSAFE_OS_STORE_IDENTITY, fileName, key).joinToString(".")

    /** The `eu.anifantakis.ksafe[.fileName]` root every [dotted] alias hangs off. */
    fun dottedBase(fileName: String?): String =
        listOfNotNull(KSAFE_OS_STORE_IDENTITY, fileName).joinToString(".")

    /**
     * Colon spelling for the stores whose records already sit in a KSafe-owned namespace (the JVM
     * vault, the web key store): `[fileName:]key`.
     */
    fun colon(fileName: String?, key: String): String =
        fileName?.let { "$it:$key" } ?: key

    /**
     * Master alias for a store whose platform HAS a device-lock split (Android Keystore, Apple
     * Keychain): the two access policies live under distinct physical keys.
     */
    fun dottedMaster(fileName: String?, requireUnlockedDevice: Boolean): String =
        dotted(fileName, if (requireUnlockedDevice) KSafeReservedKeys.MASTER_LOCKED else KSafeReservedKeys.MASTER)

    /**
     * Master alias for a store whose platform has NO device lock (JVM vault, web key store):
     * both access policies collapse onto the one master. Deliberately ignores the policy — see
     * [dottedMaster] for the platforms that don't.
     */
    fun colonMaster(fileName: String?): String = colon(fileName, KSafeReservedKeys.MASTER)
}

/**
 * Where a key actually lives, as one answer. `getKeyInfo` reports it in two vocabularies
 * ([KSafeKeyStorage] and [KSafeProtectionLevel]), and every shell used to decide twice — the
 * pair could disagree only by a typo.
 */
internal enum class KSafeKeyTier {
    SOFTWARE,

    /** No [KSafeKeyStorage] spelling exists (that vocabulary describes device key hardware), so
     *  it projects to [KSafeKeyStorage.SOFTWARE] — what the sandbox-backed shells report. */
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

/**
 * Applies the deprecated per-instance StrongBox / Secure Enclave opt-in to one write: only an
 * unqualified `DEFAULT` encrypted write is promoted, so a per-write protection always wins.
 */
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
