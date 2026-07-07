package eu.anifantakis.lib.ksafe.internal

/**
 * Pure classification step of the Apple orphan sweep: returns the key-id of an
 * orphaned KSafe key to delete, or `null` if it must be preserved. Kept free of
 * Keychain I/O (which fails with `errSecNotAvailable` in sandboxed test
 * processes) so the decision is unit-testable on every platform.
 */
internal fun keychainOrphanKeyId(
    accountOrTag: String,
    prefix: String,
    fileName: String?,
    validKeys: Set<String>,
    reservedKeyIds: Set<String>,
    isInFlight: (String) -> Boolean = { false },
    ownedKeyIds: Set<String> = emptySet(),
): String? {
    if (!accountOrTag.startsWith(prefix)) return null
    val keyId = accountOrTag.removePrefix(prefix)
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
    return keyId
}

/**
 * Delete-time gate for the Apple orphan sweep: drops classified orphans that
 * became in-flight since classification. Writes run in parallel with the sweep,
 * so a key re-used after classification but before deletion would have its live
 * key destroyed; re-checking [isInFlight] immediately before each delete closes
 * that window. Kept pure so the two-phase guarantee is unit-testable.
 */
internal fun keychainOrphansToDelete(
    classifiedOrphans: Set<String>,
    isInFlight: (String) -> Boolean,
): List<String> = classifiedOrphans.filter { !isInFlight(it) }
