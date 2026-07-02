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
    /**
     * Key-ids this instance can PROVE it owns (its live [validKeys]). A NAMED instance
     * only reaps a key-id it provably owns (FEEDBACK_4 M-D): the account
     * `KEY.fileName.keyId` is byte-identical to a ROOT instance's dotted user key
     * `fileName.keyId` (user keys are unvalidated and may contain dots), so a bare key-id
     * is genuinely ambiguous — reaping it could destroy a live foreign HARDWARE key. A
     * cross-session orphan a named instance can't prove it owns is therefore left as
     * harmless clutter (reclaimed by `clearAll()`), never auto-reaped. Ignored for the
     * root/no-fileName sweep (`fileName == null`), whose dotted-key guard above already
     * defers ambiguous ids to the named instances that own them.
     */
    ownedKeyIds: Set<String> = emptySet(),
): String? {
    if (!accountOrTag.startsWith(prefix)) return null
    val keyId = accountOrTag.removePrefix(prefix)
    if (fileName == null && keyId.contains('.')) return null
    if (keyId in reservedKeyIds) return null
    // A named instance can't prove ownership of a bare key-id (see [ownedKeyIds]); one it
    // can't prove is its own might be a live root-instance dotted key, so preserve it
    // rather than reaping (M-D). The root sweep is unaffected (fileName == null).
    if (fileName != null && keyId !in ownedKeyIds) return null
    if (keyId in validKeys) return null
    if (isInFlight(keyId)) return null
    return keyId
}

/**
 * Final delete-time gate for the Apple orphan sweep: given the set of key-ids
 * [keychainOrphanKeyId] classified as orphans, drops any that have become
 * in-flight *since classification*, and returns those still safe to delete.
 *
 * The sweep classifies on a frozen DataStore snapshot on `collectorScope`, then
 * deletes Keychain items on the same pass — but writes run on `writeScope`,
 * genuinely in parallel on Native. A `put` that commits ciphertext and re-uses a
 * key AFTER it was classified but BEFORE it is deleted would otherwise have its
 * live key destroyed, making the just-written value undecryptable (FEEDBACK_4
 * H-B). A write marks its key in-flight (dirty) at call time, before its commit
 * lands, so re-checking [isInFlight] immediately before each delete closes the
 * window that the classify-time check alone left open. Kept pure so the two-phase
 * (classify → re-check) guarantee is unit-testable without a live Keychain.
 */
internal fun keychainOrphansToDelete(
    classifiedOrphans: Set<String>,
    isInFlight: (String) -> Boolean,
): List<String> = classifiedOrphans.filter { !isInFlight(it) }
