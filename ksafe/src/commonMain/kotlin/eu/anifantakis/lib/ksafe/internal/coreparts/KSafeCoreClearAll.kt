package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.aliasWithGeneration
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.ownsPerEntryAlias
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlinx.coroutines.CancellationException

/** The wipe for [clearAll]; runs on the write consumer and also clears every sibling core's caches. */
internal suspend fun KSafeCore.performClearAll() {
    // Bump first: a cache merge whose snapshot predates this wipe must see it and redo itself,
    // or it republishes the wiped state after clearAll returns.
    while (true) {
        val e = clearEpoch.get()
        if (clearEpoch.compareAndSet(e, e + 1)) break
    }
    val protectionSnapshot = protectionMap.snapshot()
    val encMetaSnapshot = encMetaMap.snapshot()
    // An entry can record a generation above the store's; its master must still be swept.
    var maxRecordedGeneration = currentKeyGeneration.get()
    for (meta in encMetaSnapshot.values) {
        if (meta.keyGeneration > maxRecordedGeneration) maxRecordedGeneration = meta.keyGeneration
    }
    // No key material is reclaimed until the data wipe itself succeeds.
    storage.clear()
    memoryCache.clear()
    plaintextCache.clear()
    protectionMap.clear()
    encMetaMap.clear()
    // Only entries that used a per-entry alias: a no-op delete can destroy a sibling store's key.
    for ((userKey, literal) in protectionSnapshot) {
        val protection = KeySafeMetadataManager.parseProtection(literal) ?: continue
        val meta = encMetaSnapshot[userKey]
        val usedPerEntryAlias = ownsPerEntryAlias(
            protection,
            meta?.envelopeVersion ?: KeySafeMetadataManager.ENVELOPE_VERSION_V1,
        )
        if (!usedPerEntryAlias) continue
        // Every generation, not just the recorded one: a swallowed rotation cleanup strands aliases.
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
    for (reqUnlocked in listOf(false, true)) {
        for (gen in 1..maxRecordedGeneration) {
            deleteEngineKeyBestEffort(
                aliasWithGeneration(masterAlias(reqUnlocked), gen),
                attempt = "clearAll could not delete master key",
                consequence = "data wiped; key material may remain in the platform vault",
            )
        }
    }
    // storage.clear() took the persisted keygen record with it, so the store restarts at 1.
    currentKeyGeneration.set(1)
    siblings?.others(this)?.forEach { it.onSiblingClearAll() }
    // The wipe removed key records an engine may still cache; a stale cache encrypts with dead keys.
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
