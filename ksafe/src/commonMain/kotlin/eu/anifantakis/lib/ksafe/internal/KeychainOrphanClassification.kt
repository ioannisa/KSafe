package eu.anifantakis.lib.ksafe.internal

/**
 * A classified orphan: the physical [keyId] to delete, plus the logical [owner]
 * that in-flight tracking is keyed by.
 */
internal data class KeychainOrphan(val keyId: String, val owner: String)

/**
 * Classifies one Keychain entry: the orphan to delete, or `null` to preserve. [keyNamespace] must
 * match the owning `KSafeCore`'s, or no strict-variant key-id resolves back to its user key.
 */
internal fun keychainOrphanKeyId(
    accountOrTag: String,
    prefix: String,
    fileName: String?,
    validKeys: Set<String>,
    reservedKeyIds: Set<String>,
    isInFlight: (String) -> Boolean = { false },
    ownedKeyIds: Set<String> = emptySet(),
    keyNamespace: String? = fileName,
): KeychainOrphan? {
    if (!accountOrTag.startsWith(prefix)) return null
    val keyId = accountOrTag.removePrefix(prefix)
    // Strict-variant ids classify by their recovered owner; the guards below would keep every one.
    // A `.gN` before the sentinel may be generation or key text; only a unique fingerprint match wins.
    STRICT_VARIANT_KEY_ID_SUFFIX.find(keyId)?.let { m ->
        val genPart = m.groupValues[1]
        val fingerprint = m.groupValues[2]
        val candidates = buildSet {
            add(keyId.removeRange(m.range))
            if (genPart.isNotEmpty()) add(keyId.substring(0, m.range.first + genPart.length))
        }
        val owner = candidates.singleOrNull {
            KSafeCore.aliasFingerprint(keyNamespace, it) == fingerprint
        } ?: return null
        if (fileName == null && owner.contains('.')) return null
        if (fileName != null && owner !in ownedKeyIds) return null
        if (owner in validKeys) return null
        if (isInFlight(owner)) return null
        return KeychainOrphan(keyId, owner)
    }
    // Rotated relaxed ids carry a `.gN.__ksafe_gen__.h<fp>` suffix absent from validKeys; the
    // guards below preserve them — superseded generations are reclaimed by rotateKeys.
    // Root sweep: a dotted key-id belongs to a named instance; leave it alone.
    if (fileName == null && keyId.contains('.')) return null
    // Master sentinels back every DEFAULT value and never appear in validKeys.
    if (keyId in reservedKeyIds) return null
    // Named sweep: `KEY.fileName.keyId` is byte-identical to a root instance's dotted user key,
    // so only reap ids this instance provably owns.
    if (fileName != null && keyId !in ownedKeyIds) return null
    if (keyId in validKeys) return null
    // An in-flight write's key hasn't reached validKeys yet; deleting it destroys an acked write.
    if (isInFlight(keyId)) return null
    return KeychainOrphan(keyId, owner = keyId)
}

// Strict-variant tail of a per-entry key-id; see `KSafeCore.strictPerEntryAliasWithGeneration`.
private val STRICT_VARIANT_KEY_ID_SUFFIX =
    Regex(
        "(${KSafeAliasGrammar.GENERATION_PATTERN})?" +
            """\.${KSafeReservedKeys.STRICT_VARIANT}${KSafeAliasGrammar.FINGERPRINT_PATTERN}$"""
    )

/** User keys the store still vouches for; a Keychain key outside this set has no entry to decrypt. */
internal fun keychainSweepValidKeys(
    snapshot: Map<String, StoredValue>,
    legacyEncryptedPrefix: String,
): Set<String> {
    val protectionByKey = protectionByKeyFromSnapshot(snapshot)
    val validKeys = mutableSetOf<String>()
    for ((rawKey, _) in snapshot) {
        when {
            rawKey.startsWith(legacyEncryptedPrefix) ->
                validKeys.add(rawKey.removePrefix(legacyEncryptedPrefix))

            rawKey.startsWith(KeySafeMetadataManager.VALUE_PREFIX) -> {
                val userKey = rawKey.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
                if (protectionByKey[userKey] != null) validKeys.add(userKey)
            }
        }
    }
    return validKeys
}

/**
 * Fail-closed gate: `true` means delete nothing this pass. Orphans beside an empty [validKeys] mean
 * a partial view of the store, not a post-clearAll — and Secure Enclave keys cannot be recreated.
 */
internal fun keychainOrphanSweepBlocked(
    validKeys: Set<String>,
    orphanCount: Int,
): Boolean = orphanCount > 0 && validKeys.isEmpty()

/**
 * Delete-time gate: drops orphans whose owner went in-flight since classification. Keyed by the
 * logical owner to match the dirty tracking — a strict variant's physical id would never match.
 */
internal fun keychainOrphansToDelete(
    classifiedOrphans: Set<KeychainOrphan>,
    isInFlight: (String) -> Boolean,
): List<String> = classifiedOrphans.filter { !isInFlight(it.owner) }.map { it.keyId }
