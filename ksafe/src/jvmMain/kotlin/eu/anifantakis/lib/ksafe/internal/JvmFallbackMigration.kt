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
 * starting on the normal OS-backed DataStore path **for the first time** (no
 * `.preferences_pb` yet — typically the user added `modules("jdk.unsupported")`
 * and rebuilt), this carries the user's data forward instead of letting it look
 * empty: every fallback entry is decrypted with the old software key and
 * re-encrypted under the OS-backed key, then written into the DataStore.
 *
 * Re-encryption — not a raw copy — is deliberate: the data ends up protected by
 * a freshly minted OS-backed key, and the old software master key is never
 * imported into the OS keychain. Per-entry [KSafeProtection], envelope version,
 * and unlock policy are preserved (metadata is carried over verbatim). The
 * source files are **renamed** to `*.migrated`, never deleted, so the original
 * encrypted data + keys stay recoverable and the migration cannot re-fire.
 *
 * Best-effort and non-fatal: any failure (a single bad entry, or the whole
 * pass) is swallowed so it can never block construction. Runs synchronously
 * (`runBlocking`) so the data is in place before [KSafeCore] preloads — but only
 * when fallback files actually exist, so the common path pays nothing.
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
            // Only migrate into an *empty* OS-backed store. This is the first-
            // launch signal — and crucially it still fires when a prior launch
            // already created an empty `.preferences_pb` (file present but no
            // user data). It never clobbers a store that already holds real
            // data: in that case the user has moved on, and silently overwriting
            // it with older fallback data would be the worse outcome.
            val targetHasUserData = target.snapshot().keys.any {
                it.startsWith(KeySafeMetadataManager.VALUE_PREFIX)
            }
            if (targetHasUserData) return@runBlocking

            val migScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
            val migrated = try {
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

            if (migrated > 0) {
                // Archive (not delete): keep the originals recoverable and stop
                // the migration from re-triggering on the next launch.
                runCatching { jsonFallback.renameTo(File(jsonFallback.parentFile, jsonFallback.name + ".migrated")) }
                runCatching { keysFallback.renameTo(File(keysFallback.parentFile, keysFallback.name + ".migrated")) }
                warnMigratedFromFallbackOnce(migrated)
            }
        }
    }
}

/**
 * Re-encrypts every user entry from [source]/[sourceEngine] into
 * [target]/[targetEngine] under the **same** key alias (only the key store
 * changes). Returns the number of user entries carried over.
 */
@OptIn(ExperimentalEncodingApi::class)
private suspend fun reEncryptAll(
    source: KSafePlatformStorage,
    sourceEngine: KSafeEncryption,
    target: KSafePlatformStorage,
    targetEngine: KSafeEncryption,
    keyAlias: (String) -> String,
    masterAlias: (Boolean) -> String,
): Int {
    val snap = source.snapshot()
    val ops = mutableListOf<StorageOp>()
    var count = 0

    for ((rawKey, stored) in snap) {
        val userKey = KeySafeMetadataManager.tryExtractCanonicalValueKey(rawKey) ?: continue
        val metaRaw = (snap[KeySafeMetadataManager.metadataRawKey(userKey)] as? StoredValue.Text)?.value
        val protection = KeySafeMetadataManager.parseProtection(metaRaw)

        if (protection == null) {
            // Plain entry — copy value + metadata verbatim, no crypto.
            ops += StorageOp.Put(rawKey, stored)
            if (metaRaw != null) {
                ops += StorageOp.Put(KeySafeMetadataManager.metadataRawKey(userKey), StoredValue.Text(metaRaw))
            }
            count++
            continue
        }

        val cipherB64 = (stored as? StoredValue.Text)?.value ?: continue
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
        if (ok) count++
    }

    if (ops.isNotEmpty()) target.applyBatch(ops)
    return count
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
