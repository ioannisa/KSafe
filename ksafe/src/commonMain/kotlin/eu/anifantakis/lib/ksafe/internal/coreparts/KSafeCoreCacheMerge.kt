package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.KSafeBase64
import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.internal.KSafeConcurrentMap
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.encMetaFromRaw
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.toCacheValue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

/**
 * Stores [fresh] only while the slot still holds [observed]: writers set their dirty flag first, so
 * a racer fails this CAS. A racer that wrote a value equal to [observed] loses too — undoing after
 * the store would instead lose the commoner racer that wrote the disk value.
 */
private fun <V : Any> KSafeConcurrentMap<V>.storeUnclaimed(key: String, observed: V?, fresh: V): Boolean =
    if (observed == null) putIfAbsent(key, fresh) == null else replaceIf(key, observed, fresh)

/** One snapshot-merge pass; [KSafeCore.updateCache] owns the retry and the clear-epoch protocol. */
internal suspend fun KSafeCore.updateCacheOnce(snapshot: Map<String, StoredValue>) {
    val currentDirty = dirtyKeys.snapshot()
    val existingMetadata = protectionMap.snapshot()
    val validCacheKeys = mutableSetOf<String>()

    // Never move the generation backwards; an absent record is authoritative (base generation).
    (snapshot[KeySafeMetadataManager.KEYGEN_RAW_KEY] as? StoredValue.Text)?.value?.let { raw ->
        currentKeyGeneration.raiseToAtLeast(KeySafeMetadataManager.parseKeyGeneration(raw))
    }
    keyGenerationReconciled.set(true)

    fun isDirtyForUserKey(userKey: String): Boolean {
        val canonical = valueRawKey(userKey)
        val legacyEncrypted = legacyEncryptedRawKey(userKey)
        return canonical in currentDirty || userKey in currentDirty || legacyEncrypted in currentDirty
    }

    // Frozen plus LIVE check: a write landing after the snapshot must not revert to disk state.
    fun isDirtyForUserKeyLive(userKey: String): Boolean =
        isDirtyForUserKey(userKey) || isUserKeyDirty(userKey)

    val metadataEntries = snapshot.map { (rawKey, storedValue) ->
        rawKey to (storedValue as? StoredValue.Text)?.value
    }
    val protectionByKey = KeySafeMetadataManager.collectMetadata(
        entries = metadataEntries,
        accept = { userKey -> !isDirtyForUserKey(userKey) }
    ).toMutableMap()

    // encMetaMap is populated BEFORE the decrypt pass — aliasForRead consults it.
    for ((userKey, rawMeta) in protectionByKey) {
        if (KeySafeMetadataManager.parseProtection(rawMeta) == null) continue
        val observed = encMetaMap[userKey]
        if (isDirtyForUserKeyLive(userKey)) continue
        cacheMergeMetaStoreHook?.invoke(userKey)
        encMetaMap.storeUnclaimed(userKey, observed, encMetaFromRaw(rawMeta))
    }

    // Decrypts are deferred to a concurrent second pass: serialised keystore IPC dominates cold start.
    data class PendingDecrypt(
        val userKey: String,
        val cacheKey: String,
        val ciphertextB64: String,
        val protection: KSafeProtection,
    )
    val pendingDecrypts = mutableListOf<PendingDecrypt>()

    for ((rawKey, storedValue) in snapshot) {
        val classified = KeySafeMetadataManager.classifyStorageEntry(
            rawKey = rawKey,
            legacyEncryptedPrefix = legacyEncryptedPrefix,
            encryptedCacheKeyForUser = { k -> legacyEncryptedRawKey(k) },
            stagedMetadata = protectionByKey,
            existingMetadata = existingMetadata,
        ) ?: continue

        val userKey = classified.userKey
        val cacheKey = classified.cacheKey
        val explicitEncrypted = classified.encrypted

        if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKey(userKey)) {
            protectionByKey[userKey] = KeySafeMetadataManager.protectionToLiteral(
                if (explicitEncrypted) KSafeProtection.DEFAULT else null
            )
        }

        if (isDirtyForUserKey(userKey) || cacheKey in currentDirty) {
            validCacheKeys.add(cacheKey)
            continue
        }

        validCacheKeys.add(cacheKey)

        if (explicitEncrypted) {
            hasAnyEncryptedKey.set(true)
            val encryptedString = (storedValue as? StoredValue.Text)?.value ?: continue
            // Strict entries stay ciphertext under any policy, so every read hits the native lock.
            val strict = encMetaMap[userKey]?.requireUnlockedDevice == true
            if (cacheHoldsCiphertext || strict) {
                // Live re-check: a write landing after the snapshot must not lose to the disk value.
                val previousCiphertext = memoryCache[cacheKey]
                if (!isUserKeyDirty(userKey)) {
                    cacheMergeStoreHook?.invoke(userKey)
                    val stored = memoryCache.storeUnclaimed(cacheKey, previousCiphertext, encryptedString)
                    // Changed ciphertext means an external write (fresh IV per encrypt) — evict,
                    // or LAZY_PLAIN_TEXT serves the stale plaintext forever.
                    if (stored && usesPlaintextSideCache && previousCiphertext != encryptedString) {
                        plaintextCache.remove(cacheKey)
                    }
                }
            } else {
                val protection = KeySafeMetadataManager.parseProtection(protectionByKey[userKey])
                    ?: KSafeProtection.DEFAULT
                pendingDecrypts += PendingDecrypt(userKey, cacheKey, encryptedString, protection)
            }
        } else {
            val observed = memoryCache[cacheKey]
            if (!isUserKeyDirty(userKey)) {
                cacheMergeStoreHook?.invoke(userKey)
                memoryCache.storeUnclaimed(cacheKey, observed, storedValue.toCacheValue())
            }
        }
    }

    if (pendingDecrypts.isNotEmpty()) {
        val gate = Semaphore(maxParallelEncrypts)
        coroutineScope {
            pendingDecrypts.map { p ->
                async {
                    gate.withPermit {
                        try {
                            // Future-format entries fail closed: kept out of the cache, not misread.
                            val plain = decryptEntry(
                                p.userKey, p.protection, KSafeBase64.decode(p.ciphertextB64),
                                encMetaMap[p.userKey],
                            )
                            // Live re-check after the slow decrypt: a write that landed meanwhile wins.
                            val observed = memoryCache[p.cacheKey]
                            if (!isUserKeyDirty(p.userKey)) {
                                cacheMergeStoreHook?.invoke(p.userKey)
                                memoryCache.storeUnclaimed(p.cacheKey, observed, plain.decodeToString())
                            }
                        } catch (e: Throwable) {
                            if (e is CancellationException) throw e
                            /* leave out of cache */
                        }
                    }
                }
            }.awaitAll()
        }
    }

    validCacheKeys.addAll(currentDirty)

    for ((key, observed) in memoryCache.snapshot()) {
        if (key !in validCacheKeys && !dirtyKeys.contains(key)) {
            memoryCache.removeIf(key, observed)
            // Mirror the removal, or never-expiring LAZY_PLAIN_TEXT keeps serving deleted plaintext.
            if (usesPlaintextSideCache) plaintextCache.remove(key)
        }
    }

    for ((userKey, rawMeta) in protectionByKey) {
        val observed = protectionMap[userKey]
        if (!isDirtyForUserKeyLive(userKey)) {
            protectionMap.storeUnclaimed(
                userKey, observed, KeySafeMetadataManager.extractProtectionLiteral(rawMeta),
            )
        }
    }
    for ((userKey, observed) in protectionMap.snapshot()) {
        if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKeyLive(userKey)) {
            protectionMap.removeIf(userKey, observed)
        }
    }

    for ((userKey, observed) in encMetaMap.snapshot()) {
        if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKeyLive(userKey)) {
            encMetaMap.removeIf(userKey, observed)
        }
    }

    cacheInitialized.set(true)
}
