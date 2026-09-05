package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.aadForEnvelope
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.aliasForRecordedMeta
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.ownsPerEntryAlias
import eu.anifantakis.lib.ksafe.internal.KSafeCore.EncMeta
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CancellationException

/** Whether a write keys under the strict alias VARIANT; [aliasForWrite] must agree with it. */
internal fun strictAliasVariantFor(protection: KSafeProtection?, requireUnlockedDevice: Boolean): Boolean =
    protection == KSafeProtection.HARDWARE_ISOLATED && requireUnlockedDevice

/** The routing record a write commits; its four fields always move together. */
internal fun encMetaForWrite(
    protection: KSafeProtection?,
    requireUnlockedDevice: Boolean,
    keyGeneration: Int,
): EncMeta = EncMeta(
    envelopeVersion = KeySafeMetadataManager.envelopeVersionForWrite(keyGeneration),
    requireUnlockedDevice = requireUnlockedDevice,
    keyGeneration = keyGeneration,
    strictAliasVariant = strictAliasVariantFor(protection, requireUnlockedDevice),
)

/** The routing a NO-record entry defaults to: a pre-v2 per-entry alias, no associated data. */
internal val NO_RECORD_META = EncMeta(
    envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_V1,
    requireUnlockedDevice = false,
    keyGeneration = 1,
    strictAliasVariant = false,
)

internal fun KSafeCore.metaRawKey(key: String): String = KeySafeMetadataManager.metadataRawKey(key)

/** Whether [snapshot] holds a value for [userKey]; a lone metadata record is a torn write. */
internal fun KSafeCore.hasAnyValueRecord(
    snapshot: Map<String, StoredValue>,
    userKey: String,
): Boolean =
    snapshot.containsKey(valueRawKey(userKey)) ||
        snapshot.containsKey(legacyEncryptedRawKey(userKey)) ||
        snapshot.containsKey(userKey)

internal fun KSafeCore.legacyProtectionRawKey(key: String): String =
    KeySafeMetadataManager.legacyProtectionRawKey(key)

internal fun KSafeCore.buildMetaJson(
    protection: KSafeProtection?,
    requireUnlockedDevice: Boolean? = null,
    keyGeneration: Int = 1,
): String {
    val accessPolicy = if (protection == null) null
    else KeySafeMetadataManager.accessPolicyFor(requireUnlockedDevice == true)
    return KeySafeMetadataManager.buildMetadataJson(
        protection,
        accessPolicy,
        envelopeVersion = if (protection != null) {
            KeySafeMetadataManager.envelopeVersionForWrite(keyGeneration)
        } else KeySafeMetadataManager.ENVELOPE_VERSION_LATEST,
        keyGeneration = keyGeneration,
        strictAliasVariant = strictAliasVariantFor(protection, requireUnlockedDevice == true),
    )
}

/**
 * Every per-entry alias [userKey] may still own. Both spellings are enumerated — a tighten that
 * minted the strict variant and then failed to commit leaves a key under it.
 */
internal fun KSafeCore.perEntryAliasesThrough(
    userKey: String,
    recordedGeneration: Int,
    entryUsedStrictAlias: Boolean = false,
): List<String> {
    // Both bounds: a concurrent rotation may have raised the store's generation past the sampled
    // one, and an entry recorded above the store's generation keeps its own.
    val topGeneration = maxOf(recordedGeneration, currentKeyGeneration.get())
    val out = ArrayList<String>(topGeneration * 2)
    for (generation in 1..topGeneration) {
        out += perEntryAlias(userKey, generation)
        // Rotation keeps a strict entry strict even where a new user write could not mint that spelling.
        if (strictAliasVariantReachable || entryUsedStrictAlias) {
            out += strictPerEntryAlias(userKey, generation)
        }
    }
    return out
}

/**
 * Whether deleting [key] sweeps per-entry aliases: true only when the record proves the entry used
 * one — a derived alias can be another store's live key. Must run BEFORE the optimistic removal.
 */
internal fun KSafeCore.deleteTargetsPerEntryAlias(key: String): Boolean {
    val protection = protectionMap[key]?.let { KeySafeMetadataManager.parseProtection(it) } ?: return false
    return ownsPerEntryAlias(
        protection,
        encMetaMap[key]?.envelopeVersion ?: KeySafeMetadataManager.ENVELOPE_VERSION_V1,
    )
}

/**
 * The per-entry alias this write moves the entry off, captured BEFORE the optimistic [encMetaMap]
 * overwrite; null if it stays. Reclaimed only after the commit, so a failure stays decryptable.
 */
internal fun KSafeCore.capturePerEntryAliasChange(
    key: String,
    protection: KSafeProtection,
    requireUnlockedDevice: Boolean,
    writeKeyGeneration: Int,
): String? {
    if (!deleteTargetsPerEntryAlias(key)) return null
    val recordedProtection = protectionMap[key]?.let { KeySafeMetadataManager.parseProtection(it) }
    val oldAlias = aliasForRead(key, recordedProtection)
    val newAlias = aliasForWrite(key, protection, requireUnlockedDevice, writeKeyGeneration)
    return oldAlias.takeIf { it != newAlias }
}

/** [aadForRead]'s twin for a caller holding a snapshot's parsed meta instead of [encMetaMap]. */
internal fun KSafeCore.aadForRawMeta(
    userKey: String, protection: KSafeProtection?, requireUnlocked: Boolean,
    keyGeneration: Int, envelopeVersion: Int,
): ByteArray? =
    aadForEnvelope(storeIdentity, userKey, protection, requireUnlocked, keyGeneration, envelopeVersion)

/** Fallback-identity AAD for an entry; null when there is no distinct identity to retry under. */
internal fun KSafeCore.fallbackAadFor(
    userKey: String, protection: KSafeProtection?, requireUnlocked: Boolean,
    keyGeneration: Int, envelopeVersion: Int,
): ByteArray? {
    if (!hasFallbackIdentity) return null
    return aadForEnvelope(
        fallbackStoreIdentity, userKey, protection, requireUnlocked, keyGeneration, envelopeVersion,
    )
}

/** The alias and AAD pair one recorded routing resolves to; see [decryptEntry]. */
internal class DecryptRoute(
    val alias: String,
    val primaryAad: ByteArray?,
    val fallbackAad: ByteArray?,
)

/** Everything a decrypt needs from ONE routing record; fails closed on a future envelope. */
internal fun KSafeCore.decryptRoute(
    userKey: String,
    protection: KSafeProtection?,
    envelopeVersion: Int,
    requireUnlockedDevice: Boolean,
    keyGeneration: Int,
    strictAliasVariant: Boolean,
): DecryptRoute {
    KeySafeMetadataManager.checkKnownEnvelopeVersion(envelopeVersion, userKey)
    return DecryptRoute(
        alias = aliasForRawMeta(
            userKey, protection, envelopeVersion, requireUnlockedDevice,
            keyGeneration, strictAliasVariant,
        ),
        primaryAad = aadForRawMeta(
            userKey, protection, requireUnlockedDevice, keyGeneration, envelopeVersion,
        ),
        fallbackAad = fallbackAadFor(
            userKey, protection, requireUnlockedDevice, keyGeneration, envelopeVersion,
        ),
    )
}

/** [decryptRoute] for a parsed record; a null [meta] is the no-record default. */
internal fun KSafeCore.decryptRoute(
    userKey: String,
    protection: KSafeProtection?,
    meta: EncMeta?,
): DecryptRoute = (meta ?: NO_RECORD_META).let {
    decryptRoute(
        userKey, protection,
        it.envelopeVersion, it.requireUnlockedDevice, it.keyGeneration, it.strictAliasVariant,
    )
}

/** The fallback-identity retry policy, shared by the suspending and the blocking read path. */
internal inline fun decryptUnderRoute(
    route: DecryptRoute,
    ciphertext: ByteArray,
    requireUnlockedDevice: Boolean,
    decrypt: (String, ByteArray, Boolean, ByteArray?) -> ByteArray,
): ByteArray {
    if (route.fallbackAad == null) {
        return decrypt(route.alias, ciphertext, requireUnlockedDevice, route.primaryAad)
    }
    return try {
        decrypt(route.alias, ciphertext, requireUnlockedDevice, route.primaryAad)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        decrypt(route.alias, ciphertext, requireUnlockedDevice, route.fallbackAad)
    }
}

/** Decrypts an entry whose recorded routing is known; a null [meta] is the no-record default. */
internal suspend fun KSafeCore.decryptEntry(
    userKey: String,
    protection: KSafeProtection?,
    ciphertext: ByteArray,
    meta: EncMeta?,
): ByteArray = decryptUnderRoute(
    decryptRoute(userKey, protection, meta),
    ciphertext,
    meta?.requireUnlockedDevice == true,
) { alias, bytes, unlocked, aad -> engine.decryptSuspend(alias, bytes, unlocked, aad = aad) }

/** Blocking twin of [decryptEntry] for the synchronous read path. */
internal fun KSafeCore.decryptEntryBlocking(
    userKey: String,
    protection: KSafeProtection?,
    ciphertext: ByteArray,
    meta: EncMeta?,
): ByteArray = decryptUnderRoute(
    decryptRoute(userKey, protection, meta),
    ciphertext,
    meta?.requireUnlockedDevice == true,
) { alias, bytes, unlocked, aad -> engine.decrypt(alias, bytes, unlocked, aad = aad) }

/** [aliasForRawMeta] for a parsed record; a null [meta] is the no-record default. */
internal fun KSafeCore.aliasForRawMeta(
    userKey: String,
    protection: KSafeProtection?,
    meta: EncMeta?,
): String = (meta ?: NO_RECORD_META).let {
    aliasForRawMeta(
        userKey, protection,
        it.envelopeVersion, it.requireUnlockedDevice, it.keyGeneration, it.strictAliasVariant,
    )
}

/** [aliasForRead]'s twin for a caller holding a snapshot's parsed meta instead of [encMetaMap]. */
internal fun KSafeCore.aliasForRawMeta(
    userKey: String,
    protection: KSafeProtection?,
    envelopeVersion: Int,
    requireUnlockedDevice: Boolean,
    keyGeneration: Int,
    strictAliasVariant: Boolean,
): String = aliasForRecordedMeta(
    userKey, protection, envelopeVersion, requireUnlockedDevice, keyGeneration,
    strictAliasVariant, masterAlias, keyAlias, keyNamespace,
)
