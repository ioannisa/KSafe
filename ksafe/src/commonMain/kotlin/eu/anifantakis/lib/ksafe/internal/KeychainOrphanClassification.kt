package eu.anifantakis.lib.ksafe.internal

/**
 * A classified orphan: the physical [keyId] to delete plus the LOGICAL [owner] user key it
 * belongs to. Both are needed because dirty/in-flight tracking is keyed by user key — a
 * delete-time guard checking the physical id of a strict-variant key would never match a
 * concurrent write's dirty mark and could reap the key between its encrypt and commit.
 */
internal data class KeychainOrphan(val keyId: String, val owner: String)

/**
 * Pure classification step of the Apple orphan sweep: returns the orphaned key to delete
 * (with its logical owner), or `null` if it must be preserved. Kept free of Keychain I/O
 * (which fails with `errSecNotAvailable` in sandboxed test processes) so the decision is
 * unit-testable.
 *
 * [keyNamespace] must equal the owning `KSafeCore`'s `keyNamespace` (KSafe.apple
 * passes `fileName` for both) — it feeds the fingerprint check that resolves a
 * strict-variant key-id to its owning user key.
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
    // Strict-variant key-ids ("<key>[.gN].__ksafe_strict__.h<fp>", 3.0.0+) are classified by
    // their recovered owning user key — the generic dotted/owned guards below would preserve
    // every variant forever (stranding uninstall-orphaned strict keys and their SE artifacts).
    // A `.gN` run before the sentinel is AMBIGUOUS: it may be the variant's generation suffix
    // (owner excludes it) or literal characters of a user key like "foo.g2" (owner keeps it).
    // The fingerprint hashes (namespace, owner), so exactly one candidate can match; a foreign
    // or corrupt id — or the astronomically unlikely double match — resolves to no owner and
    // is preserved. Preserve-on-ambiguity still applies to the resolved owner; a live or
    // in-flight owner (including a failed tighten's virgin key, reused by the retry) is never
    // reaped.
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
    // Rotated relaxed key-ids carry a `.gN.__ksafe_gen__.h<fp>` suffix absent from
    // validKeys/ownedKeyIds; the guards below preserve them (superseded generations are
    // reclaimed by rotateKeys, not this sweep).
    // Root sweep: a dotted key-id belongs to a named instance; leave it alone.
    if (fileName == null && keyId.contains('.')) return null
    // Master sentinels back every DEFAULT value collectively and never appear in
    // validKeys; deleting one would orphan ALL DEFAULT ciphertext.
    if (keyId in reservedKeyIds) return null
    // Named sweep: the account `KEY.fileName.keyId` is byte-identical to a root
    // instance's dotted user key (user keys may contain dots), so a bare key-id is
    // ambiguous — only reap ids this instance provably owns ([ownedKeyIds]).
    if (fileName != null && keyId !in ownedKeyIds) return null
    if (keyId in validKeys) return null
    // A still-in-flight write's key hasn't reached validKeys yet (its commit lands
    // after the sweep's snapshot); deleting it would destroy an acknowledged write.
    if (isInFlight(keyId)) return null
    return KeychainOrphan(keyId, owner = keyId)
}

/**
 * Strict-variant tail of a per-entry key-id; see `KSafeCore.strictPerEntryAliasWithGeneration`.
 * The sentinel comes from the registry the alias writer uses, so a re-spelling cannot leave this
 * sweep silently matching nothing (it contains no regex metacharacter).
 */
private val STRICT_VARIANT_KEY_ID_SUFFIX =
    Regex(
        "(${KSafeAliasGrammar.GENERATION_PATTERN})?" +
            """\.${KSafeReservedKeys.STRICT_VARIANT}${KSafeAliasGrammar.FINGERPRINT_PATTERN}$"""
    )

/**
 * User keys the store still vouches for: every key whose entry the sweep can see on disk, either
 * as a legacy encrypted record ([legacyEncryptedPrefix]) or as a canonical value record carrying
 * recorded protection. A Keychain key outside this set has no entry to decrypt, which is what
 * makes it a candidate orphan — so this set is also the store's evidence that its encrypted view
 * is intact. Pure (and here rather than beside the Keychain I/O) so both roles are testable.
 */
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
 * Fail-closed gate on the whole Apple sweep: `true` means delete nothing this pass.
 *
 * Scoped Keychain entries alongside a store that vouches for NO encrypted entry
 * ([keychainSweepValidKeys] empty) signal a partial view of the store — a failed 1.x → 2.0
 * migration, a quarantined-corrupt file, a restore that brought the Keychain back but not the
 * DataStore — not a genuine post-clearAll state. Deleting there destroys Secure Enclave keys that
 * cannot be recreated, so the sweep stands down and leaves reclaimable litter instead.
 *
 * Deliberately NOT "the store is empty": one surviving record of any other kind — a reserved
 * rotation-state entry, a plaintext setting written after the loss — would then vouch for an
 * encrypted view it says nothing about, and the sweep would reap every live key.
 */
internal fun keychainOrphanSweepBlocked(
    validKeys: Set<String>,
    orphanCount: Int,
): Boolean = orphanCount > 0 && validKeys.isEmpty()

/**
 * Delete-time gate for the Apple orphan sweep: drops classified orphans whose OWNER became
 * in-flight since classification. A key re-used by a parallel write after classification but
 * before deletion would otherwise have its live key destroyed; re-checking [isInFlight]
 * immediately before each delete closes that window. The check is keyed by the LOGICAL
 * owner, matching the dirty tracking — checking a strict variant's physical id would never
 * match and the gate would silently pass a concurrent strict write's key to deletion.
 */
internal fun keychainOrphansToDelete(
    classifiedOrphans: Set<KeychainOrphan>,
    isInFlight: (String) -> Boolean,
): List<String> = classifiedOrphans.filter { !isInFlight(it.owner) }.map { it.keyId }
