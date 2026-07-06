package eu.anifantakis.lib.ksafe.internal

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
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * One-time **forward migration**: software JSON fallback → OS-backed DataStore.
 *
 * Runs when a previous launch persisted through the no-`sun.misc.Unsafe`
 * fallback ([DataStoreJsonStorage] + [FileKeyVault]) and the app now has the
 * OS-backed path. Each entry is decrypted with the old software key and
 * re-encrypted under a fresh OS-backed key (never a raw copy — the software
 * master key is never imported into the OS keychain); per-entry
 * [KSafeProtection], envelope version, and unlock policy are carried verbatim.
 *
 * **The fallback wins:** at this transition the fallback was the live store,
 * so its values overwrite anything in the target. The source files are
 * **renamed** to `*.migrated` (never deleted) once the pass has no *transient*
 * failure, so the drain happens exactly once and the originals stay
 * recoverable. Permanently unmigratable entries (corrupt ciphertext, lost
 * software key) do NOT block archiving — they fail identically every launch,
 * and re-running would roll the user's newer OS-backed writes back to stale
 * fallback data. Only a transient target-vault failure blocks archiving, and
 * then nothing is applied, so the retry has no partial state to roll back.
 *
 * Best-effort and non-fatal: any failure is swallowed so it can never block
 * construction. Runs synchronously (`runBlocking`) so the data is in place
 * before [KSafeCore] preloads — but only when a fallback file exists, so the
 * common path pays nothing.
 */
internal fun migrateJsonFallbackToOsBacked(
    config: KSafeConfig,
    jsonFallback: File,
    keysFallback: File,
    target: KSafePlatformStorage,
    targetEngine: KSafeEncryption,
    keyAlias: (String) -> String,
    masterAlias: (Boolean) -> String,
) {
    runCatching {
        runBlocking {
            // State of the target at the FIRST transiently-failed attempt (see
            // below). Present ⇒ this run is a RETRY and the session(s) since may
            // have written newer values into the target.
            val pendingFile = File(jsonFallback.parentFile, jsonFallback.name + ".migration-pending")
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
            // A present-but-unreadable pending file (a partial write from process death / full
            // disk at record time) still PROVES this run is a RETRY: the first-attempt session
            // ran on the target and may have written newer values. Falling through to null would
            // re-enable "fallback wins" for every key and silently roll those writes back
            // (FEEDBACK_4 H5). Treat it as a retry with an UNKNOWN baseline instead —
            // conservatively keep any key the target already holds a value for.
            val unknownRetryBaseline = pendingExists && priorTargetState == null

            val migScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            val result = try {
                val source = DataStoreJsonStorage(jsonFallback, migScope)
                val sourceEngine = JvmSoftwareEncryption(
                    config = config,
                    vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
                )
                reEncryptAll(source, sourceEngine, target, targetEngine, keyAlias, masterAlias, priorTargetState, unknownRetryBaseline)
            } finally {
                // Release the .ksafe.json DataStore handle before renaming the file.
                migScope.coroutineContext[Job]?.cancelAndJoin()
            }

            // Archive unless a TRANSIENT failure occurred. Permanent per-entry
            // failures must not block archiving: they recur every launch and the
            // re-run would overwrite the user's newer OS-backed writes with stale
            // fallback values. On a transient failure reEncryptAll applied
            // nothing, so the retry has no partial state to roll back.
            if (result.transientFailed == 0) {
                val markedJson = archiveOrMark(jsonFallback)
                val markedKeys = archiveOrMark(keysFallback)
                // Drop the retry-safety `.migration-pending` state only once the
                // migration is DURABLY marked done. If (rarely) even the 0-byte
                // sentinel could not be written, leaving any prior pending state in
                // place lets a forced re-run skip already-migrated keys instead of
                // re-draining stale fallback over the user's newer writes (H-C).
                if (markedJson && markedKeys) {
                    runCatching { pendingFile.delete() }
                }
            } else if (!pendingFile.exists()) {
                // FIRST transient failure: the session proceeds on the OS-backed
                // store, so the user may write newer values for the keys this
                // migration will retry. Record the target's current per-key state
                // so the retry can tell "unchanged since the failed attempt"
                // (fallback still newest → overwrite) from "user wrote it after
                // the attempt" (fallback superseded → keep the user's value).
                // Recorded once and kept until a successful migration deletes it.
                runCatching {
                    val json = Json.encodeToString(
                        MapSerializer(String.serializer(), String.serializer()),
                        result.targetStateForPending,
                    )
                    // Atomic publish: write a temp file then rename it into place, so a crash /
                    // full disk mid-write can't leave a truncated pending file (FEEDBACK_4 H5).
                    // pendingFile doesn't exist here (guarded by !pendingFile.exists()), so the
                    // rename has no destination to clobber; only a blocked rename falls back to a
                    // direct write (and the corrupt-pending handling above is the safety net).
                    val tmp = File(pendingFile.parentFile, pendingFile.name + ".tmp")
                    tmp.writeText(json)
                    if (!tmp.renameTo(pendingFile)) {
                        tmp.copyTo(pendingFile, overwrite = true)
                        tmp.delete()
                    }
                }
            }
            if (result.migrated > 0) warnMigratedFromFallbackOnce(result.migrated)
        }
    }
}

private data class MigrationResult(
    val migrated: Int,
    /** Entries permanently unmigratable (corrupt source / lost software key). Do NOT block archiving. */
    val permanentlySkipped: Int,
    /** Entries that failed for a transient reason (OS vault unavailable). Block archiving → retry. */
    val transientFailed: Int,
    /**
     * Fingerprints of the TARGET's current value per fallback canonical key,
     * captured from the same target snapshot the pass compared against —
     * persisted as the `.migration-pending` state when a transient failure
     * forces a retry.
     */
    val targetStateForPending: Map<String, String> = emptyMap(),
)

/** Marker fingerprint for "the target had no value for this key". */
private const val ABSENT_FINGERPRINT = "∅"

/**
 * Stable equality fingerprint of a target value, for the retry-overwrite
 * decision. Only compared (never reconstructed), so a type-tagged string is
 * enough; [StoredValue.Text] covers every value KSafe itself writes.
 */
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
 * Re-encrypts every user entry from [source]/[sourceEngine] into
 * [target]/[targetEngine] under the **same** key alias (only the key store
 * changes), overwriting any existing target value. Returns the counts of
 * migrated and failed entries.
 *
 * [priorTargetState] is non-null on a RETRY after a transiently-failed
 * attempt: it holds the target's per-key fingerprints recorded at that failed
 * attempt. The "fallback wins" rule is only sound when the target holds
 * nothing newer than the fallback — true on a first attempt, but sessions
 * after a failed attempt run on the target, so writes there ARE newer. A key
 * whose target value changed since the recorded state is skipped (the user's
 * value wins; the fallback copy stays recoverable in the archive); an
 * unchanged key still migrates.
 */
@OptIn(ExperimentalEncodingApi::class)
private suspend fun reEncryptAll(
    source: KSafePlatformStorage,
    sourceEngine: KSafeEncryption,
    target: KSafePlatformStorage,
    targetEngine: KSafeEncryption,
    keyAlias: (String) -> String,
    masterAlias: (Boolean) -> String,
    priorTargetState: Map<String, String>? = null,
    unknownRetryBaseline: Boolean = false,
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

        // Record the target's current state for this key (pending-state capture)
        // and, on a retry, skip a key the user wrote after the failed attempt.
        val valueKey = KeySafeMetadataManager.valueRawKey(userKey)
        val nowFingerprint = storedFingerprint(targetSnap[valueKey])
        targetFingerprints[valueKey] = nowFingerprint
        if (priorTargetState != null &&
            nowFingerprint != (priorTargetState[valueKey] ?: ABSENT_FINGERPRINT)
        ) {
            // Newer user write in the target — the fallback copy is superseded.
            // Resolved, not failed: doesn't block the apply or the archiving.
            continue
        }
        if (unknownRetryBaseline && nowFingerprint != ABSENT_FINGERPRINT) {
            // Corrupt-but-present pending file: this IS a retry, but the baseline is
            // unknown, so any non-absent target value could be a newer user write.
            // Conservatively keep it — migrate only keys the target lacks (FEEDBACK_4 H5).
            // The fallback copy stays recoverable in the `.migrated` archive.
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
            // Encrypted metadata but no text ciphertext: the value row is gone
            // (orphaned metadata) or a non-Text remnant. There is nothing
            // decryptable to carry forward, and it is a PERMANENT state — counting
            // it as a failure would block archiving forever and re-run the whole
            // (blocking) migration on every launch. Skip it; nothing is lost.
            continue
        }
        val version = KeySafeMetadataManager.parseEnvelopeVersion(metaRaw)
        val requireUnlocked = KeySafeMetadataManager.parseRequireUnlockedDevice(metaRaw)
        // Same alias formula as KSafeCore.aliasForRead / aliasForWrite: a v2
        // DEFAULT entry rides the master key; HARDWARE_ISOLATED (and any v1
        // entry) uses the per-entry alias. The decrypt alias equals the
        // re-encrypt alias — only the backing key store differs.
        val alias = if (
            version >= KeySafeMetadataManager.ENVELOPE_VERSION_V2 &&
            protection == KSafeProtection.DEFAULT
        ) {
            masterAlias(requireUnlocked)
        } else {
            keyAlias(userKey)
        }

        // Source decrypt: the fallback is a static file, so a failure here
        // (corrupt ciphertext/base64, lost/rotated software key) is PERMANENT —
        // it fails identically every launch. Skip it rather than blocking
        // archiving forever; the entry stays recoverable in the .migrated archive.
        val plain = try {
            sourceEngine.decryptSuspend(alias, Base64.decode(cipherB64))
        } catch (e: Throwable) {
            permanentlySkipped++
            continue
        }

        // Target re-encrypt: the OS-backed vault. A failure here is typically
        // TRANSIENT (vault temporarily unavailable / device locked). Block
        // archiving so the migration retries next launch — and because the apply
        // below is gated on `transientFailed == 0`, nothing is written this
        // launch, so the retry can't roll a newer write back over a partial state.
        val reCipher = try {
            targetEngine.encryptSuspend(
                identifier = alias,
                data = plain,
                hardwareIsolated = protection == KSafeProtection.HARDWARE_ISOLATED,
                requireUnlockedDevice = requireUnlocked,
            )
        } catch (e: Throwable) {
            transientFailed++
            continue
        }

        ops += StorageOp.Put(KeySafeMetadataManager.valueRawKey(userKey), StoredValue.Text(Base64.encode(reCipher)))
        ops += StorageOp.Put(KeySafeMetadataManager.metadataRawKey(userKey), StoredValue.Text(metaRaw!!))
        migrated++
    }

    // All-or-nothing on a transient failure: if any entry needs a retry, apply
    // NOTHING this launch (no partial drain that a re-run could later roll back).
    // Permanent skips don't block the apply — the successful entries land and the
    // source gets archived so the migration never re-runs.
    if (transientFailed == 0 && ops.isNotEmpty()) target.applyBatch(ops)
    return MigrationResult(
        migrated = migrated,
        permanentlySkipped = permanentlySkipped,
        transientFailed = transientFailed,
        targetStateForPending = targetFingerprints,
    )
}

/**
 * Archives a drained fallback file to `<name>.migrated` and returns whether a
 * done-marker FILE exists afterwards. Renames when possible (preserving the
 * original, recoverable); if the rename is blocked — e.g. a lingering Windows
 * file handle just after `cancelAndJoin` — it copies to the `.migrated` marker
 * instead, leaving the (now-redundant) original in place; and if BOTH are blocked
 * (permissions/AV lock/disk full) it falls back to an empty 0-byte sentinel.
 *
 * The sentinel matters: the marker's essential job is to make `buildJvmKSafe`'s
 * gate treat the migration as done. Without a durable marker the gate re-runs the
 * blocking migration on every launch as a FIRST attempt and re-drains the stale
 * fallback over whatever the user wrote in between — a perpetual silent rollback
 * (FEEDBACK_4 H-C). A successful migration has just written the OS-backed store
 * into this same directory, so a 0-byte sentinel here virtually always succeeds;
 * `false` is returned only for a fully unwritable directory (in which the
 * migration's own store write could not have succeeded either), so the caller
 * can withhold the "done" signal.
 *
 * The three I/O steps are injectable so a test can force rename+copy to fail and
 * prove the sentinel still marks the migration done; production always uses the
 * real filesystem operations. Best-effort throughout.
 */
internal fun archiveOrMark(
    f: File,
    rename: (File, File) -> Boolean = { src, dst -> src.renameTo(dst) },
    copy: (File, File) -> Boolean = { src, dst -> runCatching { src.copyTo(dst, overwrite = true) }.isSuccess },
    touch: (File) -> Boolean = { dst -> runCatching { dst.createNewFile() }.getOrDefault(false) },
): Boolean {
    val archived = File(f.parentFile, f.name + ".migrated")
    if (archived.isFile) return true // already archived/marked by an earlier pass
    if (f.exists()) {
        if (rename(f, archived) && archived.isFile) return true
        if (copy(f, archived) && archived.isFile) {
            // Rename failed but copy succeeded → the LIVE source still exists, holding the
            // plaintext AES key / ciphertext. Remove it so it doesn't linger as a residual
            // secret, mirroring the rename path which MOVES the file (FEEDBACK_4 low).
            // Best-effort: if the delete is also blocked (the same handle that blocked the
            // rename), clearAll()'s residual-file sweep is the backstop.
            runCatching { f.delete() }
            return true
        }
    }
    // Rename and copy both failed (or the source is already gone). Ensure a
    // durable done-marker regardless — the archived data is only a recoverability
    // bonus; satisfying the gate is what prevents the perpetual rollback.
    return touch(archived) && archived.isFile
}

private val migratedWarned = AtomicBoolean(false)

/** One-time notice that fallback data was carried forward to the OS-backed store. */
private fun warnMigratedFromFallbackOnce(entries: Int) {
    if (migratedWarned.compareAndSet(false, true)) {
        System.err.println(
            "KSafe NOTICE: migrated $entries entr${if (entries == 1) "y" else "ies"} from the " +
                "software JSON fallback into the OS-backed DataStore (you added " +
                "`jdk.unsupported`, so the OS keyvault is now available). Values were " +
                "re-encrypted under a fresh OS-backed key; the old fallback files were " +
                "renamed to `*.migrated` (safe to delete once you've confirmed your data)."
        )
    }
}
