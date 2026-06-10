package eu.anifantakis.lib.ksafe.internal

/**
 * Pure (Keychain-I/O-free) classification step of the Apple orphan sweep
 * (`cleanupOrphanedKeychainEntries`): given a Keychain account or
 * application-tag string, decide whether it identifies an **orphaned** KSafe
 * key the sweep should delete — returning the orphan's key-id — or `null` if it
 * must be preserved (or doesn't belong to this instance).
 *
 * This is split out from the Apple-only sweep on purpose. The v2 master-key
 * data-loss bug lived entirely in this decision (the shared master sentinel was
 * wrongly classified as an orphan), yet the sweep around it is pure Keychain
 * I/O (`SecItemCopyMatching` / delete) that a sandboxed unit-test process can't
 * exercise — the iOS simulator returns `errSecNotAvailable` for a bare test
 * binary, and the macOS by-service scan doesn't surface items the same way.
 * Keeping the logic here makes it unit-testable on every platform.
 *
 * A key-id is an orphan to delete iff ALL of these hold:
 *  - [accountOrTag] is scoped to this instance (starts with [prefix]);
 *  - it isn't a foreign fileName-scoped entry observed from the no-fileName
 *    instance — when [fileName] is null, a key-id containing a further `.`
 *    belongs to a named instance and is left alone;
 *  - it isn't [reservedKeyIds] infrastructure — the v2 envelope's per-datastore
 *    master sentinels (`__ksafe_master__` / `__ksafe_master_locked__`) are
 *    referenced by every `DEFAULT` value collectively and so never appear in
 *    [validKeys]; deleting one orphans ALL `DEFAULT` ciphertext;
 *  - it isn't currently being written ([isInFlight]) — a key the engine created
 *    moments ago for a still-in-flight write hasn't reached [validKeys] yet (its
 *    DataStore commit lands after the sweep's snapshot), so the sweep would
 *    otherwise delete a key for an acknowledged write made concurrently with it
 *    (deep-review #30). Mirrors the dirty-key guard the DataStore orphan sweep uses;
 *  - it has no live DataStore counterpart ([validKeys]).
 */
internal fun keychainOrphanKeyId(
    accountOrTag: String,
    prefix: String,
    fileName: String?,
    validKeys: Set<String>,
    reservedKeyIds: Set<String>,
    isInFlight: (String) -> Boolean = { false },
): String? {
    if (!accountOrTag.startsWith(prefix)) return null
    val keyId = accountOrTag.removePrefix(prefix)
    if (fileName == null && keyId.contains('.')) return null
    if (keyId in reservedKeyIds) return null
    if (keyId in validKeys) return null
    if (isInFlight(keyId)) return null
    return keyId
}
