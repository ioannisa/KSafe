package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.CachedPlaintext
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.NULL_SENTINEL
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.encodePlainString
import eu.anifantakis.lib.ksafe.internal.KSafeCore.EncMeta
import eu.anifantakis.lib.ksafe.internal.KSafeCore.PendingWrite
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.jsonEncode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.serialization.KSerializer

/**
 * Applies a delete's optimistic in-memory state and returns the op to enqueue. Shared by the
 * fire-and-forget and the awaiting delete, which differ only in how they dispatch it: the
 * generation and per-entry-alias flag must be captured BEFORE the map wipe, so the capture and the
 * wipe cannot be allowed to drift apart into two hand-written copies.
 */
internal fun KSafeCore.stageDelete(
    key: String,
    completion: CompletableDeferred<Unit>? = null,
): PendingWrite.Delete {
    // Rollback ownership claimed before any optimistic mutation.
    val writeToken = Any().also { writeOwners[key] = it }
    val rawKey = key
    val encKeyName = legacyEncryptedRawKey(key)
    val deleteKeyGeneration = encMetaMap[key]?.keyGeneration ?: 1
    val deleteUsedStrictAlias = encMetaMap[key]?.strictAliasVariant == true
    val deleteUsedPerEntryAlias = deleteTargetsPerEntryAlias(key)
    dirtyKeys.add(rawKey)
    dirtyKeys.add(encKeyName)
    memoryCache.remove(rawKey)
    memoryCache.remove(encKeyName)
    plaintextCache.remove(rawKey)
    plaintextCache.remove(encKeyName)
    protectionMap.remove(key)
    encMetaMap.remove(key)
    return PendingWrite.Delete(
        userKey = key,
        rawCacheKey = rawKey,
        writeToken = writeToken,
        keyGeneration = deleteKeyGeneration,
        usedPerEntryAlias = deleteUsedPerEntryAlias,
        usedStrictAlias = deleteUsedStrictAlias,
        completion = completion,
    )
}

/**
 * Applies a plain write's optimistic in-memory state and returns the op to enqueue. Shared by
 * [putPlainSuspend] and `putDirectRaw`'s plain arm; the caller supplies the already-encoded value
 * (a throwing serializer must leave no trace, so encoding happens before anything here runs) and
 * chooses between awaiting the commit and being notified of a failure.
 */
internal fun KSafeCore.stagePlainWrite(
    key: String,
    toStore: Any,
    completion: CompletableDeferred<Unit>? = null,
    onWriteFailed: ((Throwable) -> Unit)? = null,
): PendingWrite.Plain {
    // Rollback ownership claimed before any optimistic mutation.
    val writeToken = Any().also { writeOwners[key] = it }
    val supersededGen =
        if (deleteTargetsPerEntryAlias(key)) maxOf(encMetaMap[key]?.keyGeneration ?: 1, 1) else 0
    val supersededStrict = supersededGen > 0 && encMetaMap[key]?.strictAliasVariant == true
    dirtyKeys.add(key)

    // Cache the value BEFORE the protection literal — the post-commit repair's orphan
    // cleanup (`!memoryCache.containsKey`) relies on this ordering.
    memoryCache[key] = toStore
    protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(null)
    encMetaMap.remove(key)
    evictEncryptedSlot(key)

    return PendingWrite.Plain(
        userKey = key,
        rawCacheKey = key,
        value = toStore,
        writeToken = writeToken,
        supersededPerEntryGeneration = supersededGen,
        supersededStrictAlias = supersededStrict,
        completion = completion,
        onWriteFailed = onWriteFailed,
    )
}

/**
 * Encodes a plain value for storage: primitives ride the store's native types, everything else
 * becomes JSON, and null becomes the sentinel. Encoding once also guarantees the cache and the
 * batch share one representation even when the serializer is non-deterministic.
 */
internal fun KSafeCore.encodePlainValue(value: Any?, serializer: KSerializer<*>): Any =
    if (value == null) NULL_SENTINEL
    else when (value) {
        is String -> encodePlainString(value)
        is Boolean, is Int, is Long, is Float, is Double -> value
        else -> jsonEncode(json, serializer, value)
    }

internal suspend fun KSafeCore.putEncryptedSuspend(
    key: String,
    value: Any?,
    protection: KSafeProtection,
    requireUnlockedDevice: Boolean,
    serializer: KSerializer<*>,
) {
    // Serialize FIRST: a throwing serializer must leave no trace (see the
    // putDirectRaw twin for the full rationale).
    val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)

    // Optimistic in-memory state (matches `putEncryptedDirect`): subsequent
    // reads from any thread see the new value the instant this returns.
    // Rollback ownership claimed before any optimistic mutation.
    val writeToken = Any().also { writeOwners[key] = it }
    val rawCacheKey = legacyEncryptedRawKey(key)
    dirtyKeys.add(rawCacheKey)
    val writeKeyGeneration = currentKeyGeneration.get()
    val supersededAlias = capturePerEntryAliasChange(key, protection, requireUnlockedDevice, writeKeyGeneration)
    protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(protection)
    encMetaMap[key] = encMetaForWrite(protection, requireUnlockedDevice, writeKeyGeneration)
    hasAnyEncryptedKey.set(true)
    memoryCache[rawCacheKey] = jsonString
    // Plain→encrypted transition: evict the stale bare `key` plain slot a prior plaintext
    // write left in RAM (see the putDirectRaw twin for the full rationale) so an upgraded
    // secret's plaintext copy doesn't linger for the process lifetime.
    memoryCache.remove(key)
    plaintextCache.remove(key)
    // Strict entries never enter the plaintext side cache; a non-strict→strict rewrite
    // also evicts any prior entry so stale plaintext doesn't linger.
    if (usesPlaintextSideCache) {
        if (requireUnlockedDevice) plaintextCache.remove(rawCacheKey)
        else plaintextCache[rawCacheKey] = CachedPlaintext(jsonString, plaintextExpiry())
    }

    // Route through the same coalescing channel as `putDirect`, but await the
    // batch's commit. Concurrent suspend `put` calls and concurrent `putDirect`
    // calls land in the same batch and share a single `applyBatch` transaction.
    val deferred = CompletableDeferred<Unit>()
    writeChannel.send(
        PendingWrite.Encrypted(
            userKey = key,
            rawCacheKey = rawCacheKey,
            jsonString = jsonString,
            protection = protection,
            requireUnlockedDevice = requireUnlockedDevice,
            writeToken = writeToken,
            keyGeneration = writeKeyGeneration,
            supersededAliases = listOfNotNull(supersededAlias),
            completion = deferred,
        )
    )
    deferred.await()
}

/**
 * Evicts a prior encrypted write's cache slots ([legacyEncryptedRawKey]) on an encrypted->plain
 * overwrite, so the old decrypted secret doesn't linger for the process lifetime. Mirrors [deleteDirect].
 */
internal fun KSafeCore.evictEncryptedSlot(key: String) {
    val encKeyName = legacyEncryptedRawKey(key)
    memoryCache.remove(encKeyName)
    plaintextCache.remove(encKeyName)
}

internal suspend fun KSafeCore.putPlainSuspend(key: String, value: Any?, serializer: KSerializer<*>) {
    // Serialize FIRST — a throwing serializer must leave no trace (see the putDirectRaw twin).
    val toStore = encodePlainValue(value, serializer)
    val deferred = CompletableDeferred<Unit>()
    writeChannel.send(stagePlainWrite(key, toStore, completion = deferred))
    deferred.await()
}
