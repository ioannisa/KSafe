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
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * One-time **forward migration**: software JSON fallback → OS-backed DataStore.
 *
 * When a previous run persisted through the no-`sun.misc.Unsafe` fallback
 * ([DataStoreJsonStorage] + a [FileKeyVault] software key) and the app is now
 * running on the normal OS-backed DataStore path (the user added
 * `modules("jdk.unsupported")` and rebuilt), this carries the user's data
 * forward instead of letting it look empty: every fallback entry is decrypted
 * with the old software key and re-encrypted under the OS-backed key, then
 * written into the DataStore.
 *
 * Re-encryption — not a raw copy — is deliberate: the data ends up protected by
 * a freshly minted OS-backed key, and the old software master key is never
 * imported into the OS keychain. Per-entry [KSafeProtection], envelope version,
 * and unlock policy are preserved (metadata carried over verbatim).
 *
 * **The fallback wins:** at the moment of this transition the fallback file is
 * the store the user was *just* using, so its values are the most recent — the
 * migration drains every fallback entry into the OS-backed store, overwriting
 * any stale value an earlier migration left there. (The OS store can't hold
 * anything newer for these keys: reaching it the first time already drained and
 * archived the fallback.) After a clean pass (no per-entry failures) the source
 * files are **renamed** to `*.migrated`, never deleted — so the data drains
 * exactly once, the originals stay recoverable, and the migration stops
 * re-scanning. This also fixes the toggle case (turn `modules` off, change a
 * value, turn it back on): the changed value carries across.
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
            val migScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            val result = try {
                val source = DataStoreJsonStorage(jsonFallback, migScope)
                val sourceEngine = JvmSoftwareEncryption(
                    config = config,
                    vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
                )
                reEncryptAll(source, sourceEngine, target, targetEngine, keyAlias, masterAlias)
            } finally {
                // Release the .ksafe.json DataStore handle before renaming the file.
                migScope.coroutineContext[Job]?.cancelAndJoin()
            }

            // Archive (not delete) only after a clean pass — a per-entry failure
            // leaves the source in place so the next launch can retry it. Retries
            // are idempotent (re-draining writes the same values again).
            if (result.failed == 0) {
                runCatching { jsonFallback.renameTo(File(jsonFallback.parentFile, jsonFallback.name + ".migrated")) }
                runCatching { keysFallback.renameTo(File(keysFallback.parentFile, keysFallback.name + ".migrated")) }
            }
            if (result.migrated > 0) warnMigratedFromFallbackOnce(result.migrated)
        }
    }
}

private data class MigrationResult(val migrated: Int, val failed: Int)

/**
 * Re-encrypts every user entry from [source]/[sourceEngine] into
 * [target]/[targetEngine] under the **same** key alias (only the key store
 * changes), overwriting any existing target value. Returns the counts of
 * migrated and failed entries.
 */
@OptIn(ExperimentalEncodingApi::class)
private suspend fun reEncryptAll(
    source: KSafePlatformStorage,
    sourceEngine: KSafeEncryption,
    target: KSafePlatformStorage,
    targetEngine: KSafeEncryption,
    keyAlias: (String) -> String,
    masterAlias: (Boolean) -> String,
): MigrationResult {
    val srcSnap = source.snapshot()
    val ops = mutableListOf<StorageOp>()
    var migrated = 0
    var failed = 0

    for ((rawKey, stored) in srcSnap) {
        val userKey = KeySafeMetadataManager.tryExtractCanonicalValueKey(rawKey) ?: continue

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
            // Encrypted entry without text ciphertext — unexpected; treat as a
            // failure so we don't archive (and lose) it.
            failed++
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

        val ok = runCatching {
            val plain = sourceEngine.decryptSuspend(alias, Base64.decode(cipherB64))
            val reCipher = targetEngine.encryptSuspend(
                identifier = alias,
                data = plain,
                hardwareIsolated = protection == KSafeProtection.HARDWARE_ISOLATED,
                requireUnlockedDevice = requireUnlocked,
            )
            ops += StorageOp.Put(KeySafeMetadataManager.valueRawKey(userKey), StoredValue.Text(Base64.encode(reCipher)))
            ops += StorageOp.Put(KeySafeMetadataManager.metadataRawKey(userKey), StoredValue.Text(metaRaw!!))
        }.isSuccess
        if (ok) migrated++ else failed++
    }

    if (ops.isNotEmpty()) target.applyBatch(ops)
    return MigrationResult(migrated, failed)
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
