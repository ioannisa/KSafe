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

/** Optimistic delete state plus the op to enqueue; captures generation/alias flags before the wipe. */
internal fun KSafeCore.stageDelete(
    key: String,
    completion: CompletableDeferred<Unit>? = null,
): PendingWrite.Delete {
    // Rollback token claimed before any optimistic mutation.
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

/** Optimistic plain-write state plus the op to enqueue; the caller passes the encoded value. */
internal fun KSafeCore.stagePlainWrite(
    key: String,
    toStore: Any,
    completion: CompletableDeferred<Unit>? = null,
    onWriteFailed: ((Throwable) -> Unit)? = null,
): PendingWrite.Plain {
    // Rollback token claimed before any optimistic mutation.
    val writeToken = Any().also { writeOwners[key] = it }
    val supersededGen =
        if (deleteTargetsPerEntryAlias(key)) maxOf(encMetaMap[key]?.keyGeneration ?: 1, 1) else 0
    val supersededStrict = supersededGen > 0 && encMetaMap[key]?.strictAliasVariant == true
    dirtyKeys.add(key)

    // Value before the protection literal; the post-commit repair's orphan cleanup relies on it.
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

/** Encodes once, so the cache and the batch share one representation even for a loose serializer. */
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
    // Serialize first: a throwing serializer must leave no trace.
    val jsonString = if (value == null) NULL_SENTINEL else jsonEncode(json, serializer, value)

    // Rollback token claimed before any optimistic mutation.
    val writeToken = Any().also { writeOwners[key] = it }
    val rawCacheKey = legacyEncryptedRawKey(key)
    dirtyKeys.add(rawCacheKey)
    val writeKeyGeneration = currentKeyGeneration.get()
    val supersededAlias = capturePerEntryAliasChange(key, protection, requireUnlockedDevice, writeKeyGeneration)
    protectionMap[key] = KeySafeMetadataManager.protectionToLiteral(protection)
    encMetaMap[key] = encMetaForWrite(protection, requireUnlockedDevice, writeKeyGeneration)
    hasAnyEncryptedKey.set(true)
    memoryCache[rawCacheKey] = jsonString
    // Plain→encrypted: drop the bare-key plain slot a prior plaintext write left in RAM.
    memoryCache.remove(key)
    plaintextCache.remove(key)
    // Strict entries never enter the plaintext side cache, and a rewrite into strict evicts it.
    if (usesPlaintextSideCache) {
        if (requireUnlockedDevice) plaintextCache.remove(rawCacheKey)
        else plaintextCache[rawCacheKey] = CachedPlaintext(jsonString, plaintextExpiry())
    }

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

/** Drops the encrypted cache slots on an encrypted→plain overwrite so old plaintext doesn't linger. */
internal fun KSafeCore.evictEncryptedSlot(key: String) {
    val encKeyName = legacyEncryptedRawKey(key)
    memoryCache.remove(encKeyName)
    plaintextCache.remove(encKeyName)
}

internal suspend fun KSafeCore.putPlainSuspend(key: String, value: Any?, serializer: KSerializer<*>) {
    // Serialize first: a throwing serializer must leave no trace.
    val toStore = encodePlainValue(value, serializer)
    val deferred = CompletableDeferred<Unit>()
    writeChannel.send(stagePlainWrite(key, toStore, completion = deferred))
    deferred.await()
}
