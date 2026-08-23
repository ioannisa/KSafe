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

/**
 * Whether a write of this shape keys under the strict per-entry alias VARIANT. One producer for
 * the whole codebase: the boolean decides what an entry's metadata CLAIMS, while [aliasForWrite]'s
 * branch decides which alias the encrypt actually USES — a copy edited on only one side leaves an
 * entry naming a key that does not hold it.
 */
internal fun strictAliasVariantFor(protection: KSafeProtection?, requireUnlockedDevice: Boolean): Boolean =
    protection == KSafeProtection.HARDWARE_ISOLATED && requireUnlockedDevice

/**
 * The routing record a write of this shape commits: envelope version, unlock policy, generation
 * and strict-alias variant always move together, so they are derived in one place.
 */
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

/**
 * The routing a NO-record entry defaults to: a pre-v2 per-entry alias with no associated data.
 * Stated once so the read path and the alias path can never resolve a legacy entry differently.
 */
internal val NO_RECORD_META = EncMeta(
    envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_V1,
    requireUnlockedDevice = false,
    keyGeneration = 1,
    strictAliasVariant = false,
)

internal fun KSafeCore.metaRawKey(key: String): String = KeySafeMetadataManager.metadataRawKey(key)

/**
 * Whether [snapshot] holds a value for [userKey] under ANY of the three layouts an entry can
 * occupy. A metadata record without one is the surviving half of a torn write: it describes
 * nothing readable, so no caller may treat it as evidence the entry exists.
 */
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
        // Fully derived: every new strict HARDWARE_ISOLATED write keys under the strict
        // alias variant (matches [aliasForWrite]'s routing — the two must never diverge).
        strictAliasVariant = strictAliasVariantFor(protection, requireUnlockedDevice == true),
    )
}

/**
 * Every per-entry alias [userKey] may still own, from generation 1 through the higher of its
 * recorded generation and the store's current one. Enumerated (never deleted here): a concurrent
 * rotation may have raised the store's generation after the caller sampled the entry's, stranding
 * the live alias, and an entry recorded ABOVE the store's generation keeps its own. Deleting an
 * absent generation is a no-op; generation 1 yields the bare alias.
 *
 * Both alias spellings are enumerated — a tighten that minted the strict variant and then failed
 * to commit leaves a key under it — except where the store's write path cannot reach that variant
 * at all ([KSafeCore.strictAliasVariantReachable]), since a delete is only free of charge on
 * platforms whose engine can no-op it.
 *
 * [entryUsedStrictAlias] overrides that prune from the entry's own recorded state. The prune asks
 * what a new USER write can carry, and rotation does not go through [KSafeCore.modeTransformer] —
 * it takes the unlock policy from the entry's metadata — so on web a legacy strict entry rotates
 * into a strict key the prune would then refuse to sweep.
 */
internal fun KSafeCore.perEntryAliasesThrough(
    userKey: String,
    recordedGeneration: Int,
    entryUsedStrictAlias: Boolean = false,
): List<String> {
    val topGeneration = maxOf(recordedGeneration, currentKeyGeneration.get())
    val out = ArrayList<String>(topGeneration * 2)
    for (generation in 1..topGeneration) {
        out += perEntryAlias(userKey, generation)
        if (strictAliasVariantReachable || entryUsedStrictAlias) {
            out += strictPerEntryAlias(userKey, generation)
        }
    }
    return out
}

/**
 * Whether deleting [key] should sweep per-entry engine aliases: true only when THIS
 * store's recorded state proves the entry used one — HARDWARE_ISOLATED, or a legacy
 * pre-v2 envelope (whose DEFAULT entries also had per-entry keys). Must run BEFORE the
 * delete's optimistic map removal. False for plain, master-riding, or unknown entries:
 * their derived alias can be byte-identical to a sibling store's live key (a dotted
 * user key vs a named store), so "harmless no-op delete" is not a safe assumption.
 */
internal fun KSafeCore.deleteTargetsPerEntryAlias(key: String): Boolean {
    val protection = protectionMap[key]?.let { KeySafeMetadataManager.parseProtection(it) } ?: return false
    return ownsPerEntryAlias(
        protection,
        encMetaMap[key]?.envelopeVersion ?: KeySafeMetadataManager.ENVELOPE_VERSION_V1,
    )
}

/**
 * Captures, at enqueue time (BEFORE the optimistic [encMetaMap] overwrite), the per-entry
 * alias the entry currently resolves to — but only when this write will move it to a
 * DIFFERENT alias: an unlock-policy transition, a legacy strict entry migrating to the
 * strict alias variant, or a per-entry entry rewritten onto a master alias. Gated on
 * proven per-entry-alias ownership ([deleteTargetsPerEntryAlias]): firing for a
 * master-riding entry would reclaim an alias this store may never have minted, and a
 * generation-1 dotted-key alias can be byte-identical to another store's live key. The
 * consumer re-compares against the alias the write ACTUALLY used (post-clamp) and
 * reclaims the old one only AFTER the commit, under the live-alias guard — never before
 * the write's own encrypt succeeds, so any failure leaves the previous value decryptable.
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

/** Fallback-identity AAD for an entry; null when there is no distinct fallback identity to
 *  retry under (or the entry is pre-v3). */
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

/**
 * Resolves everything a decrypt needs from ONE recorded routing record, so no call site
 * assembles a decrypt that reads under the wrong key or silently skips authentication.
 * Fails closed on a future envelope version before any of it is derived.
 */
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

/** [decryptRoute] for a caller holding a parsed record; a null [meta] is the no-record
 *  default (pre-v2 per-entry alias, no associated data). */
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

/**
 * The fallback-identity retry policy, written once for both the suspending and the blocking
 * read path: an entry bound to the raw path spelling still reads, and a non-AAD failure
 * (missing key) fails identically on retry and propagates unchanged.
 * [decrypt] is the engine call the caller's context allows.
 */
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

/** The decrypt entry point for an entry whose recorded routing is known; a null [meta] is
 *  the no-record default (pre-v2 per-entry alias, no associated data). */
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

/** [aliasForRawMeta] for a caller holding a parsed record; a null [meta] is the no-record
 *  default (pre-v2 per-entry alias). */
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

/** [aliasForRead]'s twin for callers holding a snapshot's parsed meta instead of
 *  [encMetaMap] (getFlow emissions, the orphan probe, rotation). */
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
