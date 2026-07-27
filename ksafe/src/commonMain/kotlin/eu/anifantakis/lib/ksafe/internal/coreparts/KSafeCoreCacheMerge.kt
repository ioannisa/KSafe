package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.KSafeBase64
import eu.anifantakis.lib.ksafe.KSafeProtection
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
 * The snapshot merge [KSafeCore.updateCache] retries around; see its contract for the
 * clear-epoch protocol this single pass deliberately does not handle itself.
 */
internal suspend fun KSafeCore.updateCacheOnce(snapshot: Map<String, StoredValue>) {
    val currentDirty = dirtyKeys.snapshot()
    val existingMetadata = protectionMap.snapshot()
    val validCacheKeys = mutableSetOf<String>()

    // Sync the store's key-rotation generation from disk. Never move backwards: a stale
    // snapshot racing a just-committed rotation must not make new writes mint keys under
    // an old (possibly already-deleted) generation. An ABSENT keygen record is just as
    // authoritative (the store is at the base generation), so the reconciled flag is set
    // either way.
    (snapshot[KeySafeMetadataManager.KEYGEN_RAW_KEY] as? StoredValue.Text)?.value?.let { raw ->
        currentKeyGeneration.raiseToAtLeast(KeySafeMetadataManager.parseKeyGeneration(raw))
    }
    keyGenerationReconciled.set(true)

    fun isDirtyForUserKey(userKey: String): Boolean {
        val canonical = valueRawKey(userKey)
        val legacyEncrypted = legacyEncryptedRawKey(userKey)
        return canonical in currentDirty || userKey in currentDirty || legacyEncrypted in currentDirty
    }

    // Frozen + LIVE dirty check for the shared metadata maps: a write landing after the
    // snapshot must not have its metadata reverted to stale disk state, while a key
    // rolled back mid-merge still defers to the rollback's own fresher re-merge.
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
        if (isDirtyForUserKeyLive(userKey)) continue
        // Skip plain entries — encMetaMap only tracks encrypted ones.
        if (KeySafeMetadataManager.parseProtection(rawMeta) == null) continue
        encMetaMap[userKey] = encMetaFromRaw(rawMeta)
    }

    // PLAIN_TEXT-memory decrypts are deferred to a concurrent second pass —
    // serialised keystore IPC dominates cold-start time on large stores.
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
            // Strict (requireUnlockedDevice) entries stay ciphertext even under a
            // plaintext policy so every read hits the native store and enforces the lock.
            val strict = encMetaMap[userKey]?.requireUnlockedDevice == true
            if (cacheHoldsCiphertext || strict) {
                // Live re-check: a write landing after the snapshot must not be
                // clobbered with the older disk value.
                if (!isUserKeyDirty(userKey)) {
                    val previousCiphertext = memoryCache[cacheKey]
                    memoryCache[cacheKey] = encryptedString
                    // A changed ciphertext means an external write (fresh IV per encrypt) —
                    // evict the stale side-cache entry, which under LAZY_PLAIN_TEXT would
                    // otherwise serve the old plaintext forever.
                    if (usesPlaintextSideCache && previousCiphertext != encryptedString) {
                        plaintextCache.remove(cacheKey)
                    }
                }
            } else {
                val protection = KeySafeMetadataManager.parseProtection(protectionByKey[userKey])
                    ?: KSafeProtection.DEFAULT
                pendingDecrypts += PendingDecrypt(userKey, cacheKey, encryptedString, protection)
            }
        } else {
            if (!isUserKeyDirty(userKey)) memoryCache[cacheKey] = storedValue.toCacheValue()
        }
    }

    // Second pass: concurrent decrypts; failures are dropped from the cache.
    if (pendingDecrypts.isNotEmpty()) {
        val gate = Semaphore(maxParallelEncrypts)
        coroutineScope {
            pendingDecrypts.map { p ->
                async {
                    gate.withPermit {
                        try {
                            // Future-format entries fail closed (left out of the cache; reads
                            // serve the default) instead of being misread as v3. Strict entries
                            // are excluded upstream; their recorded unlock policy still travels
                            // with the routing so any that slip through enforce the lock.
                            val plain = decryptEntry(
                                p.userKey, p.protection, KSafeBase64.decode(p.ciphertextB64),
                                encMetaMap[p.userKey],
                            )
                            // Live re-check after the slow decrypt: don't overwrite a write
                            // that landed during the round-trip with this stale disk value.
                            if (!isUserKeyDirty(p.userKey)) memoryCache[p.cacheKey] = plain.decodeToString()
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

    for (key in memoryCache.snapshot().keys) {
        if (key !in validCacheKeys && !dirtyKeys.contains(key)) {
            memoryCache.remove(key)
            // Mirror into the side cache — an externally deleted key's plaintext would
            // otherwise be served forever under never-expiring LAZY_PLAIN_TEXT.
            if (usesPlaintextSideCache) plaintextCache.remove(key)
        }
    }

    // Sync protectionMap from disk; live-checked so a put that changed this key's
    // protection mid-merge keeps its fresh routing metadata.
    for ((userKey, rawMeta) in protectionByKey) {
        if (!isDirtyForUserKeyLive(userKey)) {
            protectionMap[userKey] = KeySafeMetadataManager.extractProtectionLiteral(rawMeta)
        }
    }
    for (userKey in protectionMap.snapshot().keys) {
        if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKeyLive(userKey)) {
            protectionMap.remove(userKey)
        }
    }

    // Drop encMetaMap entries with no on-disk metadata (live-checked, as above).
    for (userKey in encMetaMap.snapshot().keys) {
        if (!protectionByKey.containsKey(userKey) && !isDirtyForUserKeyLive(userKey)) {
            encMetaMap.remove(userKey)
        }
    }

    cacheInitialized.set(true)
}
