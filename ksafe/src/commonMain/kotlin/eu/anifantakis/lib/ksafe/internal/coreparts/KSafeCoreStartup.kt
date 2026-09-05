package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.KSafeBase64
import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.aliasWithGeneration
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.encMetaFromRaw
import eu.anifantakis.lib.ksafe.internal.KSafeCore.EncMeta
import eu.anifantakis.lib.ksafe.internal.KSafeSecretSlots
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.ksafeLogWarning
import eu.anifantakis.lib.ksafe.internal.protectionByKeyFromSnapshot
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit

/** Creates both master keys off-thread; failures fall through to the lazy-create path. */
internal fun KSafeCore.prewarmMasterKeys() {
    writeScope.launch {
        // Generation read at execute time: on a rotated store this can warm the base
        // generation instead — a missed warm, not a correctness problem.
        val gen = currentKeyGeneration.get()
        for (requireUnlocked in listOf(false, true)) {
            try {
                engine.prewarmKey(
                    identifier = aliasWithGeneration(masterAlias(requireUnlocked), gen),
                    hardwareIsolated = false,
                    requireUnlockedDevice = requireUnlocked,
                )
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
            }
        }
        try {
            engine.prewarmDekReadIfPresent(
                aliasWithGeneration(masterAlias(false), gen),
                requireUnlockedDevice = false,
            )
        } catch (e: Throwable) {
            if (e is CancellationException) throw e
        }
    }
}

internal fun KSafeCore.startBackgroundCollector() {
    collectorScope.launch {
        // Cleanup only after the first snapshot: sweeping an empty pre-migration snapshot
        // would delete unrecreatable Secure Enclave keys as orphans.
        var firstEmission = true
        storage.snapshotFlow()
            .onEach { snapshot ->
                updateCache(snapshot)
                if (firstEmission) {
                    firstEmission = false
                    runOneTimeStartupCleanup()
                }
            }
            .retryingTransientReads { attempt, cause ->
                ksafeLogWarning(
                    "KSafe: snapshot collector read failed (attempt $attempt, " +
                        "${cause::class.simpleName}: ${cause.message}); resubscribing.",
                )
            }
            .collect { }
    }
}

/** One-shot, best-effort: access-policy migration, orphan sweep, legacy key migration, rotation. */
internal suspend fun KSafeCore.runOneTimeStartupCleanup() {
    if (!startupCleanupDone.compareAndSet(false, true)) return
    swallowingNonCancellation { migrateAccessPolicy(::isUserKeyDirty) }
    swallowingNonCancellation { cleanupOrphanedCiphertext() }
    swallowingNonCancellation { engine.migrateLegacyKeysSuspend() }
    maybeScheduleKeyRotation()
}

/** Under [lazyLoad] no collector runs, so the first access triggers the cleanup off-thread. */
internal fun KSafeCore.triggerLazyStartupCleanupOnce() {
    if (!lazyLoad || startupCleanupDone.get()) return
    if (!lazyStartupCleanupLaunched.compareAndSet(false, true)) return
    collectorScope.launch { runOneTimeStartupCleanup() }
}

/** Removes ciphertext whose decryption key is missing — permanently orphaned entries. */
internal suspend fun KSafeCore.cleanupOrphanedCiphertext() {
    val snapshot = storage.snapshot()
    val protectionByKey = protectionByKeyFromSnapshot(snapshot)

    data class Candidate(
        val rawKey: String,
        val userKey: String,
        val ciphertextB64: String,
        val protection: KSafeProtection,
        val meta: EncMeta,
    )

    val candidates = snapshot.mapNotNull { (rawKey, value) ->
        // Preserve legacy encrypted entries — they predate the canonical VALUE_PREFIX.
        if (rawKey.startsWith(legacyEncryptedPrefix)) return@mapNotNull null
        if (!rawKey.startsWith(KeySafeMetadataManager.VALUE_PREFIX)) return@mapNotNull null
        val userKey = rawKey.removePrefix(KeySafeMetadataManager.VALUE_PREFIX)
        // Reaping a getOrCreateSecret slot turns its refuse-to-rotate guard into a silent new secret.
        if (userKey.startsWith(KSafeSecretSlots.PLAIN_PREFIX) ||
            userKey.startsWith(KSafeSecretSlots.HEX_PREFIX)
        ) return@mapNotNull null
        val protection = protectionByKey[userKey] ?: return@mapNotNull null
        val encryptedString = (value as? StoredValue.Text)?.value ?: return@mapNotNull null
        // Probe from this snapshot's metadata, not encMetaMap: a concurrent rotation would make
        // a freshly-rotated entry read as a "key not found" orphan.
        val metaRaw = (snapshot[metaRawKey(userKey)] as? StoredValue.Text)?.value
            ?: (snapshot[legacyProtectionRawKey(userKey)] as? StoredValue.Text)?.value
        Candidate(
            rawKey = rawKey,
            userKey = userKey,
            ciphertextB64 = encryptedString,
            protection = protection,
            meta = encMetaFromRaw(metaRaw),
        )
    }

    if (candidates.isEmpty()) return

    val gate = Semaphore(maxParallelEncrypts)
    val orphans = coroutineScope {
        candidates.map { c ->
            async {
                gate.withPermit {
                    try {
                        // Probe with the entry's own unlock policy: a locked-device probe throws
                        // transient, not "key not found". Not decryptEntry — its legacy-identity
                        // retry would only repeat the same missing-key verdict.
                        val route = decryptRoute(c.userKey, c.protection, c.meta)
                        engine.decryptSuspend(
                            route.alias,
                            KSafeBase64.decode(c.ciphertextB64),
                            c.meta.requireUnlockedDevice,
                            aad = route.primaryAad,
                        )
                        null
                    } catch (e: Throwable) {
                        if (e is CancellationException) throw e
                        if (isOrphanProbeFailure(e)) c else null
                    }
                }
            }
        }.awaitAll().filterNotNull()
    }

    reapValuelessMetadata()

    if (orphans.isEmpty()) return

    // Re-check under the shared commit mutex: a rotation rewrites the ciphertext without marking
    // dirtyKeys, and a sibling's dirtyKeys are invisible here — a stale probe would erase a write.
    commitMutex.withLock {
        val fresh = storage.snapshot()
        val orphanOps = mutableListOf<StorageOp>()
        for (c in orphans) {
            if (isUserKeyDirty(c.userKey)) continue
            if ((fresh[c.rawKey] as? StoredValue.Text)?.value != c.ciphertextB64) continue
            orphanOps += StorageOp.Delete(c.rawKey)
            orphanOps += StorageOp.Delete(metaRawKey(c.userKey))
            orphanOps += StorageOp.Delete(legacyProtectionRawKey(c.userKey))
            memoryCache.remove(c.userKey)
            memoryCache.remove(legacyEncryptedRawKey(c.userKey))
        }
        if (orphanOps.isEmpty()) return
        storage.applyBatch(orphanOps)
    }
}

/** Deletes metadata whose value record never landed — a write torn by process death on a backend
 *  without atomic batches. Skips keys with a write in flight: that shape is also a healthy commit. */
private suspend fun KSafeCore.reapValuelessMetadata() {
    commitMutex.withLock {
        val fresh = storage.snapshot()
        val ops = mutableListOf<StorageOp>()
        for ((rawKey, storedValue) in fresh) {
            val userKey = KeySafeMetadataManager.tryExtractCanonicalMetadataKey(rawKey) ?: continue
            if ((storedValue as? StoredValue.Text) == null) continue
            if (hasAnyValueRecord(fresh, userKey)) continue
            if (isUserKeyDirty(userKey)) continue
            ops += StorageOp.Delete(rawKey)
            ops += StorageOp.Delete(legacyProtectionRawKey(userKey))
        }
        if (ops.isEmpty()) return
        storage.applyBatch(ops)
    }
}
