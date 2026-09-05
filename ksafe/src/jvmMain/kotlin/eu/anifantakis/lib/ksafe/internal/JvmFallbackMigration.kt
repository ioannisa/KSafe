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

/** Probe alias for [FileKeyVault] whole-file readability: healthy or missing returns null, corrupt throws. */
private const val WHOLE_VAULT_READ_PROBE_ALIAS = "__ksafe_migration_readability_probe__"

internal const val JSON_FALLBACK_SUFFIX: String = ".ksafe.json"

// The factory spells these too: its clearAll sweep must delete the `.migrated` archive (plaintext
// key map), and its appNamespace copy-forward must carry both or a drained fallback is re-drained.
internal const val FALLBACK_MIGRATED_SUFFIX: String = ".migrated"
internal const val FALLBACK_MIGRATION_PENDING_SUFFIX: String = ".migration-pending"

/**
 * One-time drain of the software JSON fallback into the OS-backed DataStore, archiving the source as
 * `*.migrated`. A transient vault failure applies nothing and blocks archiving, so a later launch retries.
 */
internal fun migrateJsonFallbackToOsBacked(
    config: KSafeConfig,
    jsonFallback: File,
    keysFallback: File,
    target: KSafePlatformStorage,
    targetEngine: KSafeEncryption,
    keyAlias: (String) -> String,
    masterAlias: (Boolean) -> String,
    // Must equal the KSafeCore storeIdentity byte-for-byte, or a rotated v3 entry's AAD breaks.
    storeIdentity: String = "",
    // The pre-canonicalization identity (blank when it matches storeIdentity): a v3 entry an older
    // build wrote under the raw path spelling is retried under it instead of being dropped.
    fallbackStoreIdentity: String = "",
    // Must equal the KSafeCore keyNamespace, or rotated per-entry aliases derive differently here.
    keyNamespace: String? = null,
    persistPendingState: (File, String) -> Unit = ::defaultPersistPendingState,
) {
    runCatching {
        runBlocking {
            // A `.migration-pending` file means this run is a retry: newer target values may exist.
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
            // An unreadable pending file still proves this is a retry; reading it as null would
            // re-enable "fallback wins" and roll newer writes back. Keep whatever the target holds.
            val unknownRetryBaseline = pendingExists && priorTargetState == null

            // Probe the source vault once up front. Per-alias in the loop, an outage would miscount
            // every encrypted entry as a permanent skip and archive both files, never retrying.
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
                    // Transient, not escaping: with no marker the next launch reruns as a first
                    // attempt and rolls newer OS writes back.
                    MigrationResult(migrated = 0, permanentlySkipped = 0, transientFailed = 1)
                }
            } finally {
                // Release the DataStore handle before renaming the file.
                migScope.coroutineContext[Job]?.cancelAndJoin()
            }

            // Permanent per-entry failures must not block archiving: they recur every launch, and
            // the re-run would overwrite newer OS-backed writes with stale fallback.
            if (result.transientFailed == 0) {
                val markedJson = archiveOrMark(jsonFallback)
                val markedKeys = archiveOrMark(keysFallback)
                // Drop the pending state only once the migration is durably marked done.
                if (markedJson && markedKeys) {
                    runCatching { pendingFile.delete() }
                }
            } else if (!pendingFile.exists()) {
                // Record the target's per-key state so the retry can tell "unchanged" from
                // "written since". Kept until a pass succeeds.
                runCatching {
                    val json = Json.encodeToString(
                        MapSerializer(String.serializer(), String.serializer()),
                        result.targetStateForPending,
                    )
                    persistPendingState(pendingFile, json)
                }
                // If the content couldn't be written, a 0-byte sentinel still proves this is a retry.
                if (!pendingFile.exists()) {
                    runCatching { pendingFile.createNewFile() }
                }
            }
            if (result.migrated > 0) warnMigratedFromFallbackOnce(result.migrated)
        }
    }
}

// Temp then rename, so a crash mid-write can't leave a truncated pending file.
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
    /** Corrupt source or lost software key. Does NOT block archiving. */
    val permanentlySkipped: Int,
    /** OS vault unavailable. Blocks archiving so the next launch retries. */
    val transientFailed: Int,
    val targetStateForPending: Map<String, String> = emptyMap(),
)

private const val ABSENT_FINGERPRINT = "∅"

private fun storedFingerprint(sv: StoredValue?): String = when (sv) {
    null -> ABSENT_FINGERPRINT
    is StoredValue.Text -> "T:${sv.value}"
    is StoredValue.BoolVal -> "B:${sv.value}"
    is StoredValue.IntVal -> "I:${sv.value}"
    is StoredValue.LongVal -> "L:${sv.value}"
    is StoredValue.FloatVal -> "F:${sv.value}"
    is StoredValue.DoubleVal -> "D:${sv.value}"
}

// Re-encrypts every user entry from source into target under the same key alias, overwriting existing
// values — except, on a retry, keys whose target value moved since the priorTargetState fingerprints.
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
    // A whole-vault read outage is transient: its entries block archiving instead of counting as skips.
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
            // Newer user write, so the fallback is superseded. Resolved, not failed.
            continue
        }
        // With no baseline, any non-absent value could be a newer write: migrate what's missing only.
        if (unknownRetryBaseline && nowFingerprint != ABSENT_FINGERPRINT) {
            continue
        }

        val metaRaw = (srcSnap[KeySafeMetadataManager.metadataRawKey(userKey)] as? StoredValue.Text)?.value
        val protection = KeySafeMetadataManager.parseProtection(metaRaw)

        if (protection == null) {
            ops += StorageOp.Put(rawKey, stored)
            if (metaRaw != null) {
                ops += StorageOp.Put(KeySafeMetadataManager.metadataRawKey(userKey), StoredValue.Text(metaRaw))
            }
            migrated++
            continue
        }

        val cipherB64 = (stored as? StoredValue.Text)?.value
        if (cipherB64 == null) {
            // Encrypted meta with no ciphertext: nothing to carry, and permanent — don't block archiving.
            continue
        }
        if (!sourceKeyStoreReadable) {
            transientFailed++
            continue
        }
        val version = KeySafeMetadataManager.parseEnvelopeVersion(metaRaw)
        if (version > KeySafeMetadataManager.ENVELOPE_VERSION_MAX_KNOWN) {
            // A future envelope this build can't decrypt: trying would count a permanent skip and
            // the entry would vanish into the archive, so carry the bytes forward verbatim.
            ops += StorageOp.Put(rawKey, stored)
            ops += StorageOp.Put(KeySafeMetadataManager.metadataRawKey(userKey), StoredValue.Text(metaRaw!!))
            migrated++
            continue
        }
        val requireUnlocked = KeySafeMetadataManager.parseRequireUnlockedDevice(metaRaw)
        val generation = KeySafeMetadataManager.parseKeyGeneration(metaRaw)
        val strictVariant = KeySafeMetadataManager.parseStrictAliasVariant(metaRaw)
        // Alias and AAD come from the core, never re-derived here: a wrong alias fails the source
        // decrypt and the entry is silently dropped.
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

        // The fallback is a static file, so a decrypt failure is permanent: skip rather than block
        // archiving forever, after one retry under the fallback identity.
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

        // A re-encrypt failure is transient (vault unavailable, device locked); it also gates the
        // apply below, so this launch writes nothing and leaves no partial state.
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

    // The key-generation record travels with the entry cohort, or a rotated store regresses to
    // generation 1 and the next write drops back to a v2 envelope. The target wins when ahead.
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

    // All-or-nothing on a transient failure, so a re-run has no partial drain to roll back.
    if (transientFailed == 0 && ops.isNotEmpty()) target.applyBatch(ops)
    return MigrationResult(
        migrated = migrated,
        permanentlySkipped = permanentlySkipped,
        transientFailed = transientFailed,
        targetStateForPending = targetFingerprints,
    )
}

// Archives a drained fallback to `<name>.migrated` — rename, else copy, else a 0-byte sentinel — and
// reports whether a marker exists: without one the factory's gate re-drains stale fallback each launch.
internal fun archiveOrMark(
    f: File,
    rename: (File, File) -> Boolean = { src, dst -> src.renameTo(dst) },
    copy: (File, File) -> Boolean = { src, dst -> runCatching { src.copyTo(dst, overwrite = true) }.isSuccess },
    touch: (File) -> Boolean = { dst -> runCatching { dst.createNewFile() }.getOrDefault(false) },
): Boolean {
    val archived = File(f.parentFile, f.name + FALLBACK_MIGRATED_SUFFIX)
    if (archived.isFile) {
        // A second fallback period was drained and the marker name is taken: drop the redundant
        // source and bump the marker past it, or the mtime gate keeps re-draining stale fallback.
        if (f.exists()) {
            runCatching { f.delete() }
            runCatching { archived.setLastModified(System.currentTimeMillis()) }
        }
        return true
    }
    if (f.exists()) {
        if (rename(f, archived) && archived.isFile) return true
        if (copy(f, archived) && archived.isFile) {
            // The source still holds the plaintext AES key, so drop it once the copy landed.
            runCatching { f.delete() }
            return true
        }
    }
    // The archive is a bonus; the marker is what stops the re-drain, so write one regardless.
    return touch(archived) && archived.isFile
}

private val migratedWarning = OneShotWarning()

private fun warnMigratedFromFallbackOnce(entries: Int) {
    migratedWarning.warn {
        "KSafe NOTICE: migrated $entries entr${if (entries == 1) "y" else "ies"} from the " +
            "software JSON fallback into the OS-backed DataStore (you added " +
            "`jdk.unsupported`, so the OS keyvault is now available). Values were " +
            "re-encrypted under a fresh OS-backed key; the old fallback files were " +
            "renamed to `*.migrated` (safe to delete once you've confirmed your data)."
    }
}
