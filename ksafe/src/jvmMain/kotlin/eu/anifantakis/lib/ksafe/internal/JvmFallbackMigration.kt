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
            val priorTargetState: Map<String, String>? = if (pendingFile.exists()) {
                runCatching {
                    Json.decodeFromString(
                        MapSerializer(String.serializer(), String.serializer()),
                        pendingFile.readText(),
                    )
                }.getOrNull() // unreadable/corrupt pending state ⇒ behave like a first attempt
            } else {
                null
            }

            val migScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            val result = try {
                val source = DataStoreJsonStorage(jsonFallback, migScope)
                val sourceEngine = JvmSoftwareEncryption(
                    config = config,
                    vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
                )
                reEncryptAll(source, sourceEngine, target, targetEngine, keyAlias, masterAlias, priorTargetState)
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
                archiveOrMark(jsonFallback)
                archiveOrMark(keysFallback)
                runCatching { pendingFile.delete() }
            } else if (!pendingFile.exists()) {
                // FIRST transient failure: the session proceeds on the OS-backed
                // store, so the user may write newer values for the keys this
                // migration will retry. Record the target's current per-key state
                // so the retry can tell "unchanged since the failed attempt"
                // (fallback still newest → overwrite) from "user wrote it after
                // the attempt" (fallback superseded → keep the user's value).
                // Recorded once and kept until a successful migration deletes it.
                runCatching {
                    pendingFile.writeText(
                        Json.encodeToString(
                            MapSerializer(String.serializer(), String.serializer()),
                            result.targetStateForPending,
                        )
                    )
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
 * Archives a drained fallback file to `<name>.migrated`. Renames when possible
 * (preserving the original, recoverable). If the rename is blocked — e.g. a
 * lingering Windows file handle just after `cancelAndJoin` — it copies to the
 * `.migrated` marker instead, leaving the (now-redundant) original in place.
 * Either way the marker exists afterwards, so `buildJvmKSafe`'s gate does not
 * re-run the blocking migration on every launch. Best-effort throughout.
 */
private fun archiveOrMark(f: File) {
    if (!f.exists()) return
    val archived = File(f.parentFile, f.name + ".migrated")
    if (f.renameTo(archived)) return
    runCatching { f.copyTo(archived, overwrite = true) }
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
