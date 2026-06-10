package eu.anifantakis.lib.ksafe.internal

/**
 * Pure (Keychain-I/O-free) classification step of the Apple orphan sweep
 * (`cleanupOrphanedKeychainEntries`): given a Keychain account or
 * application-tag string, returns the key-id of an **orphaned** KSafe key the
 * sweep should delete, or `null` if it must be preserved (or doesn't belong to
 * this instance).
 *
 * Kept separate from the Apple-only sweep because Keychain I/O
 * (`SecItemCopyMatching` / delete) can't run in a sandboxed unit-test process
 * (the iOS simulator returns `errSecNotAvailable` for a bare test binary);
 * keeping the decision here makes it unit-testable on every platform.
 *
 * A key-id is an orphan to delete iff ALL of these hold:
 *  - [accountOrTag] is scoped to this instance (starts with [prefix]);
 *  - it isn't a foreign fileName-scoped entry observed from the no-fileName
 *    instance — when [fileName] is null, a key-id containing a further `.`
 *    belongs to a named instance and is left alone;
 *  - it isn't [reservedKeyIds] infrastructure — the per-datastore master
 *    sentinels (`__ksafe_master__` / `__ksafe_master_locked__`) are referenced
 *    by every `DEFAULT` value collectively and so never appear in [validKeys];
 *    deleting one orphans ALL `DEFAULT` ciphertext;
 *  - it isn't currently being written ([isInFlight]) — a key created for a
 *    still-in-flight write hasn't reached [validKeys] yet (its DataStore commit
 *    lands after the sweep's snapshot), so deleting it would destroy an
 *    acknowledged concurrent write. Mirrors the dirty-key guard in the
 *    DataStore orphan sweep;
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
