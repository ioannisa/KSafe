package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.encodeBase64
import eu.anifantakis.lib.ksafe.decodeBase64
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.KSafeProtection
import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File

/**
 * Probe alias for [FileKeyVault] whole-file readability: a healthy/missing key file returns null,
 * an unreadable/corrupt one throws. Deliberately not a real key name.
 */
private const val WHOLE_VAULT_READ_PROBE_ALIAS = "__ksafe_migration_readability_probe__"

/** File-name suffix of the JVM software JSON fallback store, appended to the DataStore base name. */
internal const val JSON_FALLBACK_SUFFIX: String = ".ksafe.json"

/**
 * On-disk markers of the fallback migration, appended to a drained fallback file's name.
 *
 * Written here and matched from the factory — `clearAll`'s residue sweep must delete the
 * `.migrated` archive (it holds the full plaintext AES key map), and the appNamespace
 * copy-forward must carry both markers or an already-drained fallback is re-drained over newer
 * writes. Neither failure reports anything, so both ends spell them from here.
 */
internal const val FALLBACK_MIGRATED_SUFFIX: String = ".migrated"
internal const val FALLBACK_MIGRATION_PENDING_SUFFIX: String = ".migration-pending"

/**
 * One-time forward migration: software JSON fallback → OS-backed DataStore.
 *
 * Runs when a previous launch persisted through the no-`sun.misc.Unsafe` fallback
 * ([DataStoreJsonStorage] + [FileKeyVault]) and the app now has the OS-backed path. Each entry is
 * decrypted with the old software key and re-encrypted under a fresh OS-backed key (the software
 * master key is never imported into the OS keychain); protection, envelope version, and unlock
 * policy carry verbatim.
 *
 * Fallback wins: its values overwrite the target. Source files are renamed to `*.migrated` (never
 * deleted) once a pass has no transient failure, so the drain happens exactly once and originals
 * stay recoverable. Permanently unmigratable entries (corrupt ciphertext, lost software key) do NOT
 * block archiving — re-running would roll newer OS-backed writes back to stale fallback. Only a
 * transient target-vault failure blocks archiving, and then nothing is applied.
 *
 * Best-effort and non-fatal; failures are swallowed. Runs synchronously before [KSafeCore]
 * preloads, but only when a fallback file exists.
 */
internal fun migrateJsonFallbackToOsBacked(
    config: KSafeConfig,
    jsonFallback: File,
    keysFallback: File,
    target: KSafePlatformStorage,
    targetEngine: KSafeEncryption,
    keyAlias: (String) -> String,
    masterAlias: (Boolean) -> String,
    // Must equal the KSafeCore storeIdentity for this store BYTE-FOR-BYTE — the home-relative
    // stableStoreIdentity of the pre-namespace baseDir + baseFileName — so a rotated v3 entry's
    // AAD round-trips. (Not the raw absolute path: the identity is home-relative since the AAD
    // relocation fix.) The "" default is only a safety fallback; the live factory always passes
    // the real value.
    storeIdentity: String = "",
    // The pre-canonicalization identity (blank when it matches [storeIdentity]); a v3 entry
    // written by an older build under the raw path spelling is retried under it, so a custom
    // baseDir reached via a relative/symlinked/`..` spelling isn't dropped from the migration.
    fallbackStoreIdentity: String = "",
    // Must equal the KSafeCore keyNamespace (the fileName) so rotated per-entry aliases —
    // fingerprinted with it — derive identically here and in the live core.
    keyNamespace: String? = null,
    // Injectable for fault tests; the default is the atomic temp-write-then-rename publish.
    persistPendingState: (File, String) -> Unit = ::defaultPersistPendingState,
) {
    runCatching {
        runBlocking {
            // `.migration-pending` present ⇒ this run is a RETRY (recorded target state at the
            // first transient failure); sessions since may have written newer target values.
            val pendingFile = File(jsonFallback.parentFile, jsonFallback.name + FALLBACK_MIGRATION_PENDING_SUFFIX)
            val pendingExists = pendingFile.exists()
            val priorTargetState: Map<String, String>? = if (pendingExists) {
                runCatching {
                    Json.decodeFromString(
                        MapSerializer(String.serializer(), String.serializer()),
                        pendingFile.readText(),
                    )
                }.getOrNull()
            } else {
                null
            }
            // A present-but-unreadable pending file still proves this is a RETRY; treating it as
            // null would re-enable "fallback wins" and roll newer writes back. Retry with an
            // UNKNOWN baseline: keep any key the target already has a value for.
            val unknownRetryBaseline = pendingExists && priorTargetState == null

            // Probe the source key store's whole-file readability ONCE up front (a missing file
            // reads empty; an unreadable/corrupt one throws). Letting that surface per-alias in the
            // loop would miscount every encrypted entry as a permanent skip → both files archived,
            // never retried, data recoverable only from the .migrated archives. Mark the whole vault
            // unreadable so those entries count transient (block archiving → retry).
            val sourceKeyStoreReadable =
                runCatching { FileKeyVault(keysFallback).get(WHOLE_VAULT_READ_PROBE_ALIAS) }.isSuccess

            val migScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            val result = try {
                runCatching {
                    val source = DataStoreJsonStorage(jsonFallback, migScope)
                    val sourceEngine = JvmSoftwareEncryption(
                        config = config,
                        vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
                    )
                    reEncryptAll(source, sourceEngine, target, targetEngine, keyAlias, masterAlias, storeIdentity, fallbackStoreIdentity, keyNamespace, priorTargetState, unknownRetryBaseline, sourceKeyStoreReadable)
                }.getOrElse {
                    // A transient failure (source construction, snapshot() IOException) must not
                    // escape and abort silently — no marker means the next launch reruns as a
                    // first attempt and rolls newer OS writes back. Count transient so archiving
                    // is blocked and the pending marker is recorded.
                    MigrationResult(migrated = 0, permanentlySkipped = 0, transientFailed = 1)
                }
            } finally {
                // Release the .ksafe.json DataStore handle before renaming the file.
                migScope.coroutineContext[Job]?.cancelAndJoin()
            }

            // Archive unless a transient failure occurred. Permanent per-entry failures must not
            // block archiving — they recur every launch and the re-run would overwrite newer
            // OS-backed writes with stale fallback. On a transient failure nothing was applied.
            if (result.transientFailed == 0) {
                val markedJson = archiveOrMark(jsonFallback)
                val markedKeys = archiveOrMark(keysFallback)
                // Drop the `.migration-pending` state only once the migration is durably marked
                // done, so a forced re-run skips already-migrated keys rather than re-draining
                // stale fallback over newer writes.
                if (markedJson && markedKeys) {
                    runCatching { pendingFile.delete() }
                }
            } else if (!pendingFile.exists()) {
                // First transient failure: the session proceeds on the OS-backed store and may
                // write newer values. Record the target's per-key state so the retry can tell
                // "unchanged → overwrite" from "user wrote it after → keep". Kept until success.
                runCatching {
                    val json = Json.encodeToString(
                        MapSerializer(String.serializer(), String.serializer()),
                        result.targetStateForPending,
                    )
                    persistPendingState(pendingFile, json)
                }
                // The pending marker is the SOLE defense against a later launch re-running
                // "fallback wins" and rolling newer target writes back to stale fallback
                // values. If even its content couldn't be persisted, a 0-byte sentinel still
                // proves "this is a retry": a present-but-unreadable pending file routes to
                // the unknown-retry baseline above, which keeps any value the target holds.
                if (!pendingFile.exists()) {
                    runCatching { pendingFile.createNewFile() }
                }
            }
            if (result.migrated > 0) warnMigratedFromFallbackOnce(result.migrated)
        }
    }
}

/**
 * Atomic publish of the `.migration-pending` state: write a temp then rename it in, so a
 * crash mid-write can't leave a truncated pending file. A blocked rename falls back to a
 * direct write (the corrupt-pending handling in the caller is the safety net).
 */
private fun defaultPersistPendingState(pendingFile: File, json: String) {
    val tmp = File(pendingFile.parentFile, pendingFile.name + ".tmp")
    tmp.writeText(json)
    if (!tmp.renameTo(pendingFile)) {
        tmp.copyTo(pendingFile, overwrite = true)
        tmp.delete()
    }
}

private data class MigrationResult(
    val migrated: Int,
    /** Entries permanently unmigratable (corrupt source / lost software key). Do NOT block archiving. */
    val permanentlySkipped: Int,
    /** Entries that failed for a transient reason (OS vault unavailable). Block archiving → retry. */
    val transientFailed: Int,
    /** Per-key fingerprints of the target snapshot the pass compared against; persisted as the `.migration-pending` state on a transient failure. */
    val targetStateForPending: Map<String, String> = emptyMap(),
)

/** Marker fingerprint for "the target had no value for this key". */
private const val ABSENT_FINGERPRINT = "∅"

/** Stable equality fingerprint of a target value for the retry-overwrite decision (compared, never reconstructed). */
private fun storedFingerprint(sv: StoredValue?): String = when (sv) {
    null -> ABSENT_FINGERPRINT
    is StoredValue.Text -> "T:${sv.value}"
    is StoredValue.BoolVal -> "B:${sv.value}"
    is StoredValue.IntVal -> "I:${sv.value}"
    is StoredValue.LongVal -> "L:${sv.value}"
    is StoredValue.FloatVal -> "F:${sv.value}"
    is StoredValue.DoubleVal -> "D:${sv.value}"
}

/**
 * Re-encrypts every user entry from [source] into [target] under the same key alias (only the key
 * store changes), overwriting existing target values. Returns the migrated/failed counts.
 *
 * [priorTargetState] is non-null on a retry after a transient failure: a key whose target value
 * changed since the recorded fingerprints is skipped (the user's newer write wins), an unchanged
 * key migrates ("fallback wins" is only sound when the target holds nothing newer).
 */
private suspend fun reEncryptAll(
    source: KSafePlatformStorage,
    sourceEngine: KSafeEncryption,
    target: KSafePlatformStorage,
    targetEngine: KSafeEncryption,
    keyAlias: (String) -> String,
    masterAlias: (Boolean) -> String,
    storeIdentity: String,
    fallbackStoreIdentity: String,
    keyNamespace: String?,
    priorTargetState: Map<String, String>? = null,
    unknownRetryBaseline: Boolean = false,
    // False when the source key store couldn't be read this pass (probed up front). A whole-vault
    // read outage is transient, not per-entry permanent — its encrypted entries block archiving.
    sourceKeyStoreReadable: Boolean = true,
): MigrationResult {
    val srcSnap = source.snapshot()
    val targetSnap = target.snapshot()
    val targetFingerprints = mutableMapOf<String, String>()
    val ops = mutableListOf<StorageOp>()
    var migrated = 0
    var permanentlySkipped = 0
    var transientFailed = 0

    for ((rawKey, stored) in srcSnap) {
        val userKey = KeySafeMetadataManager.tryExtractCanonicalValueKey(rawKey) ?: continue

        val valueKey = KeySafeMetadataManager.valueRawKey(userKey)
        val nowFingerprint = storedFingerprint(targetSnap[valueKey])
        targetFingerprints[valueKey] = nowFingerprint
        if (priorTargetState != null &&
            nowFingerprint != (priorTargetState[valueKey] ?: ABSENT_FINGERPRINT)
        ) {
            // Newer user write — fallback superseded. Resolved, not failed: doesn't block archiving.
            continue
        }
        if (unknownRetryBaseline && nowFingerprint != ABSENT_FINGERPRINT) {
            // Unknown retry baseline: any non-absent target value could be a newer user write.
            // Migrate only keys the target lacks; the fallback copy stays in the `.migrated` archive.
            continue
        }

        val metaRaw = (srcSnap[KeySafeMetadataManager.metadataRawKey(userKey)] as? StoredValue.Text)?.value
        val protection = KeySafeMetadataManager.parseProtection(metaRaw)

        if (protection == null) {
            // Plain entry — copy value + metadata verbatim, no crypto.
            ops += StorageOp.Put(rawKey, stored)
            if (metaRaw != null) {
                ops += StorageOp.Put(KeySafeMetadataManager.metadataRawKey(userKey), StoredValue.Text(metaRaw))
            }
            migrated++
            continue
        }

        val cipherB64 = (stored as? StoredValue.Text)?.value
        if (cipherB64 == null) {
            // Encrypted metadata but no text ciphertext (orphaned/non-Text remnant): nothing to
            // carry forward, and permanent — skip rather than block archiving forever.
            continue
        }
        if (!sourceKeyStoreReadable) {
            // Whole-vault source read outage: every encrypted entry would fail decrypt identically.
            // Count transient (block archiving → retry) instead of draining as permanent skips.
            transientFailed++
            continue
        }
        val version = KeySafeMetadataManager.parseEnvelopeVersion(metaRaw)
        if (version > KeySafeMetadataManager.ENVELOPE_VERSION_MAX_KNOWN) {
            // Written by a newer KSafe (a future envelope this build can't decrypt): probing it
            // as v3 would fail and count it a permanent skip, and permanent skips don't block
            // archiving — the entry would vanish from the live store into the `.migrated`
            // archive. Carry the bytes forward verbatim (like a plain entry) so the KSafe that
            // wrote them still reads them; the software-fallback key travels via the vault copy.
            ops += StorageOp.Put(rawKey, stored)
            ops += StorageOp.Put(KeySafeMetadataManager.metadataRawKey(userKey), StoredValue.Text(metaRaw!!))
            migrated++
            continue
        }
        val requireUnlocked = KeySafeMetadataManager.parseRequireUnlockedDevice(metaRaw)
        val generation = KeySafeMetadataManager.parseKeyGeneration(metaRaw)
        val strictVariant = KeySafeMetadataManager.parseStrictAliasVariant(metaRaw)
        // Routing and associated data come from the core's single producers, never re-derived
        // here: a wrong alias makes the source decrypt fail and the entry is silently DROPPED,
        // and this copy has already drifted from the shared formula twice.
        val alias = KSafeCore.aliasForRecordedMeta(
            userKey = userKey,
            protection = protection,
            envelopeVersion = version,
            requireUnlockedDevice = requireUnlocked,
            keyGeneration = generation,
            strictAliasVariant = strictVariant,
            masterAlias = masterAlias,
            keyAlias = keyAlias,
            keyNamespace = keyNamespace,
        )
        val aad = KSafeCore.aadForEnvelope(
            storeIdentity, userKey, protection, requireUnlocked, generation, version,
        )
        // The pre-canonicalization identity an older build may have bound this entry under.
        val fallbackAad = if (fallbackStoreIdentity.isNotEmpty() && fallbackStoreIdentity != storeIdentity) {
            KSafeCore.aadForEnvelope(
                fallbackStoreIdentity, userKey, protection, requireUnlocked, generation, version,
            )
        } else null

        // Source decrypt: the fallback is a static file, so a failure here (corrupt ciphertext,
        // lost/rotated software key) is permanent — skip rather than block archiving forever.
        // A v3 entry written by an older build under the non-canonical path is retried under the
        // fallback identity before being counted a permanent skip.
        val plain = try {
            sourceEngine.decryptSuspend(alias, decodeBase64(cipherB64), aad = aad)
        } catch (e: Throwable) {
            val recovered = fallbackAad?.let {
                runCatching { sourceEngine.decryptSuspend(alias, decodeBase64(cipherB64), aad = it) }.getOrNull()
            }
            if (recovered == null) {
                permanentlySkipped++
                continue
            }
            recovered
        }

        // Target re-encrypt: a failure here is typically transient (vault unavailable / device
        // locked). Count transient so archiving is blocked and the apply (gated on transientFailed
        // == 0) writes nothing this launch, leaving no partial state to roll back.
        val reCipher = try {
            targetEngine.encryptSuspend(
                identifier = alias,
                data = plain,
                hardwareIsolated = protection == KSafeProtection.HARDWARE_ISOLATED,
                requireUnlockedDevice = requireUnlocked,
                aad = aad,
            )
        } catch (e: Throwable) {
            transientFailed++
            continue
        }

        ops += StorageOp.Put(KeySafeMetadataManager.valueRawKey(userKey), StoredValue.Text(encodeBase64(reCipher)))
        ops += StorageOp.Put(KeySafeMetadataManager.metadataRawKey(userKey), StoredValue.Text(metaRaw!!))
        migrated++
    }

    // Carry the store-level key-generation record with the entry cohort. Without it a migrated
    // rotated store regresses to generation 1: the next write silently drops back to a v2
    // envelope (no AAD), the MaxAge clock restarts, and a later 1→2 rotation re-targets ".g2"
    // aliases the migration already minted keys under. The target's record wins when it is
    // AHEAD (higher generation, or same generation with an older birth) — a newer OS-side
    // rotation must not be rolled back by stale fallback state.
    val srcKeygen = (srcSnap[KeySafeMetadataManager.KEYGEN_RAW_KEY] as? StoredValue.Text)?.value
    if (srcKeygen != null) {
        val dstKeygen = (targetSnap[KeySafeMetadataManager.KEYGEN_RAW_KEY] as? StoredValue.Text)?.value
        val srcGen = KeySafeMetadataManager.parseKeyGeneration(srcKeygen)
        val dstGen = dstKeygen?.let { KeySafeMetadataManager.parseKeyGeneration(it) } ?: 0
        val srcTs = KeySafeMetadataManager.parseKeyGenerationTimestamp(srcKeygen)
        val dstTs = KeySafeMetadataManager.parseKeyGenerationTimestamp(dstKeygen)
        val sourceWins = srcGen > dstGen ||
            (srcGen == dstGen && (dstTs == null || (srcTs != null && srcTs < dstTs)))
        if (sourceWins) {
            ops += StorageOp.Put(KeySafeMetadataManager.KEYGEN_RAW_KEY, StoredValue.Text(srcKeygen))
        }
    }

    // All-or-nothing on a transient failure: apply nothing this launch (no partial drain a re-run
    // could roll back). Permanent skips don't block the apply — successful entries still land.
    if (transientFailed == 0 && ops.isNotEmpty()) target.applyBatch(ops)
    return MigrationResult(
        migrated = migrated,
        permanentlySkipped = permanentlySkipped,
        transientFailed = transientFailed,
        targetStateForPending = targetFingerprints,
    )
}

/**
 * Archives a drained fallback file to `<name>.migrated` and returns whether a done-marker exists
 * afterwards. Renames when possible (preserving the original); a blocked rename (e.g. a lingering
 * Windows file handle just after `cancelAndJoin`) copies instead; both blocked falls back to a
 * 0-byte sentinel.
 *
 * The marker makes `buildJvmKSafe`'s gate treat the migration as done — without it the gate
 * re-runs every launch and re-drains stale fallback over newer writes. `false` (caller withholds
 * "done") only for a fully unwritable directory. The three I/O steps are injectable for tests.
 */
internal fun archiveOrMark(
    f: File,
    rename: (File, File) -> Boolean = { src, dst -> src.renameTo(dst) },
    copy: (File, File) -> Boolean = { src, dst -> runCatching { src.copyTo(dst, overwrite = true) }.isSuccess },
    touch: (File) -> Boolean = { dst -> runCatching { dst.createNewFile() }.getOrDefault(false) },
): Boolean {
    val archived = File(f.parentFile, f.name + FALLBACK_MIGRATED_SUFFIX)
    if (archived.isFile) {
        // Marker already exists from a prior period. A still-present source means a second fallback
        // period was drained: the marker name is taken, so remove the redundant source and bump the
        // marker mtime past it, else the mtime gate keeps re-draining stale fallback over newer writes.
        if (f.exists()) {
            runCatching { f.delete() }
            runCatching { archived.setLastModified(System.currentTimeMillis()) }
        }
        return true
    }
    if (f.exists()) {
        if (rename(f, archived) && archived.isFile) return true
        if (copy(f, archived) && archived.isFile) {
            // Copy succeeded but the source still holds the plaintext AES key / ciphertext; remove
            // it so it doesn't linger as a residual secret. If the delete is blocked, clearAll()'s
            // residual-file sweep is the backstop.
            runCatching { f.delete() }
            return true
        }
    }
    // Rename and copy both failed (or the source is gone). Ensure a durable done-marker regardless
    // — the archive is only a recoverability bonus; satisfying the gate prevents the rollback.
    return touch(archived) && archived.isFile
}

private val migratedWarning = OneShotWarning()

/** One-time notice that fallback data was carried forward to the OS-backed store. */
private fun warnMigratedFromFallbackOnce(entries: Int) {
    migratedWarning.warn {
        "KSafe NOTICE: migrated $entries entr${if (entries == 1) "y" else "ies"} from the " +
            "software JSON fallback into the OS-backed DataStore (you added " +
            "`jdk.unsupported`, so the OS keyvault is now available). Values were " +
            "re-encrypted under a fresh OS-backed key; the old fallback files were " +
            "renamed to `*.migrated` (safe to delete once you've confirmed your data)."
    }
}
