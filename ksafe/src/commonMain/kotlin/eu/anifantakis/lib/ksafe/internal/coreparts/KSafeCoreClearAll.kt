package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.aliasWithGeneration
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.ownsPerEntryAlias
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlinx.coroutines.CancellationException

/** The wipe for [clearAll]; runs on the write consumer, serialized with other writes, and also wipes every sibling core's caches. */
internal suspend fun KSafeCore.performClearAll() {
    // First: any cache merge whose snapshot predates this wipe must observe the bump and
    // redo itself, or it would republish the wiped state after clearAll returns.
    while (true) {
        val e = clearEpoch.get()
        if (clearEpoch.compareAndSet(e, e + 1)) break
    }
    // Per-entry engine keys are deleted BEFORE clearing protectionMap (the key
    // inventory). Only entries that provably USED a per-entry alias are swept:
    // v2+ DEFAULT entries ride the shared master (deleted below), and issuing the
    // no-op delete anyway would destroy a sibling store's live key when a dotted
    // user key collides with that store's alias namespace.
    val protectionSnapshot = protectionMap.snapshot()
    // Captured before the map clears below: an entry can legitimately record a generation
    // ABOVE the store's (a write that raced an earlier clearAll under the old clamp-free
    // code), and its master would otherwise survive this wipe's 1..current sweep.
    var maxRecordedGeneration = currentKeyGeneration.get()
    for (meta in encMetaMap.snapshot().values) {
        if (meta.keyGeneration > maxRecordedGeneration) maxRecordedGeneration = meta.keyGeneration
    }
    for ((userKey, literal) in protectionSnapshot) {
        val protection = KeySafeMetadataManager.parseProtection(literal) ?: continue
        val meta = encMetaMap[userKey]
        val usedPerEntryAlias = ownsPerEntryAlias(
            protection,
            meta?.envelopeVersion ?: KeySafeMetadataManager.ENVELOPE_VERSION_V1,
        )
        if (!usedPerEntryAlias) continue
        // Sweep every generation up to the store's current one, mirroring the delete()
        // path: a swallowed rotation-time cleanup may have stranded an intermediate
        // generation's alias that the entry's recorded generation no longer names.
        val aliases = perEntryAliasesThrough(
            userKey, meta?.keyGeneration ?: 1, meta?.strictAliasVariant == true,
        )
        for (alias in aliases) {
            deleteEngineKeyBestEffort(
                alias,
                attempt = "clearAll could not delete engine key",
                consequence = "data wiped; key material may remain in the platform vault",
            )
        }
    }
    storage.clear()
    memoryCache.clear()
    plaintextCache.clear()
    protectionMap.clear()
    encMetaMap.clear()
    // Drop the master keys — every generation up to the highest one any entry recorded
    // (not just the store's), so a rotated store's superseded-but-not-yet-swept keys and
    // an above-store-generation straggler's master can't outlive a full wipe.
    for (reqUnlocked in listOf(false, true)) {
        for (gen in 1..maxRecordedGeneration) {
            deleteEngineKeyBestEffort(
                aliasWithGeneration(masterAlias(reqUnlocked), gen),
                attempt = "clearAll could not delete master key",
                consequence = "data wiped; key material may remain in the platform vault",
            )
        }
    }
    // storage.clear() wiped the persisted keygen state with everything else; a fresh
    // store starts over at the base generation.
    currentKeyGeneration.set(1)
    siblings?.others(this)?.forEach { it.onSiblingClearAll() }
    // The wipe may have removed engine key records the explicit deletes above didn't
    // name (e.g. rotation-generation masters minted concurrently); an engine holding
    // them in an in-memory cache must drop it or it will keep encrypting with keys
    // that no longer exist on disk.
    swallowingNonCancellation { engine.onStoreCleared() }
}

/** `dirtyKeys`/`writeOwners` stay: the post-commit repair re-asserts an in-flight write via its owner token. */
internal fun KSafeCore.onSiblingClearAll() {
    while (true) {
        val e = clearEpoch.get()
        if (clearEpoch.compareAndSet(e, e + 1)) break
    }
    memoryCache.clear()
    plaintextCache.clear()
    protectionMap.clear()
    encMetaMap.clear()
    currentKeyGeneration.set(1)
}
