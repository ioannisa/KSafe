package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.KSafeBase64
import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.aliasWithGeneration
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.encMetaFromRaw
import eu.anifantakis.lib.ksafe.internal.KSafeCore.EncMeta
import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage
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

/**
 * Eagerly creates both master keys (relaxed + strict) off-thread. Failures are
 * swallowed — the lazy-create path retries on the first real write.
 */
internal fun KSafeCore.prewarmMasterKeys() {
    writeScope.launch {
        // Generation read at execute time; on a rotated store this may still race the
        // first snapshot and warm the base generation — harmless (writes lazily create
        // the right key), just a missed warm.
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
        // Read-only warm of an already-persisted relaxed DEK so the first encrypted
        // read doesn't block the caller thread on storage I/O; never creates a DEK.
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
        // Startup cleanup runs only AFTER the first snapshot emission: sweeping against
        // an empty pre-migration snapshot would treat every Keychain key as orphaned and
        // delete unrecreatable Secure Enclave keys.
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

/**
 * One-time post-first-load cleanup: access-policy migration, orphan-ciphertext sweep,
 * and legacy key-material migration. Best-effort and idempotent; must run only after
 * the first snapshot has populated the cache.
 */
internal suspend fun KSafeCore.runOneTimeStartupCleanup() {
    if (!startupCleanupDone.compareAndSet(false, true)) return
    swallowingNonCancellation { migrateAccessPolicy(::isUserKeyDirty) }
    swallowingNonCancellation { cleanupOrphanedCiphertext() }
    swallowingNonCancellation { engine.migrateLegacyKeysSuspend() }
    maybeScheduleKeyRotation()
}

/**
 * Under [lazyLoad] no collector runs, so the startup cleanup is triggered once by the
 * first access — on the background scope so it never blocks the read.
 */
internal fun KSafeCore.triggerLazyStartupCleanupOnce() {
    if (!lazyLoad || startupCleanupDone.get()) return
    if (!lazyStartupCleanupLaunched.compareAndSet(false, true)) return
    collectorScope.launch { runOneTimeStartupCleanup() }
}

/** Removes ciphertext whose decryption key is missing — permanently orphaned entries. */
internal suspend fun KSafeCore.cleanupOrphanedCiphertext() {
    val snapshot = storage.snapshot()
    val protectionByKey = protectionByKeyFromSnapshot(snapshot)

    // Candidates are collected first so the decrypt probes run concurrently,
    // semaphore-capped keystore IPC.
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
        val protection = protectionByKey[userKey] ?: return@mapNotNull null
        val encryptedString = (value as? StoredValue.Text)?.value ?: return@mapNotNull null
        // Route the probe from the SAME snapshot's metadata, not a stale encMetaMap generation a
        // concurrent rotation could make disagree — else a freshly-rotated entry reads as a
        // false "key not found" orphan.
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
                        // Future-format entries throw inside decryptRoute (a message the
                        // orphan patterns below never match) — preserved, never probed as v3.
                        // Probe with the candidate's own recorded unlock policy: a locked-device
                        // probe throws transient, not "key not found", so strict entries aren't
                        // misclassified as orphans. Deliberately NOT decryptEntry: a legacy-identity
                        // retry would only repeat the same missing-key verdict this probe asks for.
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
                        val msg = e.message.orEmpty()
                        if (msg.contains(KSafeEngineMessage.NO_KEY, true) ||
                            msg.contains(KSafeEngineMessage.KEY_NOT_FOUND, true) ||
                            msg.contains(KSafeEngineMessage.WEB_KEY_MISSING, true)
                        ) c else null
                    }
                }
            }
        }.awaitAll().filterNotNull()
    }

    reapValuelessMetadata()

    if (orphans.isEmpty()) return

    // CAS the on-disk ciphertext before deleting: a rotation that committed after the probe
    // snapshot rewrites it, and rotations don't mark dirtyKeys so isUserKeyDirty can't catch
    // them — deleting on the stale probe would drop a now-recoverable entry. The whole
    // check+delete holds the shared commit mutex: a sibling same-file instance's dirtyKeys
    // are invisible here, so without it a sibling could commit a fresh value between this
    // snapshot and the applyBatch and the delete would erase an acknowledged write.
    commitMutex.withLock {
        val fresh = storage.snapshot()
        val orphanOps = mutableListOf<StorageOp>()
        for (c in orphans) {
            // Live re-check: a write racing the sweep marks the key dirty before committing;
            // deleting its ciphertext here would silently revert an acknowledged write.
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

/**
 * Removes metadata records whose value never landed — the surviving half of a write torn by
 * process death on a backend without multi-key atomicity. Such a record already reads back as the
 * caller's default, so deleting it loses nothing; leaving it accumulates junk that no other pass
 * enumerates (rotation needs a ciphertext, the orphan sweep walks value records).
 *
 * The same discipline as the orphan sweep guards it: the whole scan+delete holds the commit mutex,
 * so no half-applied batch of this process is ever visible, and a key with a write in flight is
 * skipped — on a backend that commits metadata first, "metadata without a value" is also the
 * transient shape of a perfectly healthy write.
 *
 * On a backend whose `applyBatch` is atomic this is a no-op by construction: every producer of a
 * metadata record emits its value record in the SAME batch, so the pair can only be split by a
 * process death partway through a non-atomic apply.
 */
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
