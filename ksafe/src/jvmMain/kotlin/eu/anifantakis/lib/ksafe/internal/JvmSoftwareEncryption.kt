package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStoreKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.keyvault.resolveJvmAppNamespace
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * JVM [KSafeEncryption]: software AES-256-GCM (`javax.crypto`) for the payload, with the
 * AES key itself protected by an OS secret store via [JvmKeyVault] — DPAPI on Windows,
 * login Keychain on macOS (SE-gated on Apple Silicon / T2), Secret Service / libsecret
 * on Linux.
 *
 * When no OS store is reachable, [JvmKeyVaultProvider] falls back to a Base64-in-DataStore
 * scheme and logs a one-time security warning. A key already in the DataStore file is
 * migrated on first read: copied into the OS store, then removed from the file. The crypto
 * (random 12-byte IV, IV‖ciphertext layout) is unchanged, so data survives the migration.
 *
 * @property config Key-generation configuration (key size).
 * @property dataStore Backs the legacy/fallback vault and the Windows DPAPI vault.
 */
@PublishedApi
internal class JvmSoftwareEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    // Null on the no-DataStore JSON-file fallback path, which supplies a vaultProvider instead.
    dataStore: DataStore<Preferences>? = null,
    // Test seam / fallback wiring: inject a vault provider and bypass OS detection.
    vaultProvider: JvmKeyVaultProvider? = null,
) : KSafeEncryption {

    companion object {
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
    }

    private val vaults: JvmKeyVaultProvider =
        vaultProvider ?: JvmKeyVaultProvider(
            requireNotNull(dataStore) {
                "JvmSoftwareEncryption requires a dataStore unless a vaultProvider is provided"
            },
            resolveJvmAppNamespace(config.appNamespace),
        )

    /** Active vault name — exposed for tests/diagnostics, not public API. */
    @PublishedApi
    internal val keyVaultName: String get() = vaults.active.name

    /** True iff the active vault is OS-backed (DPAPI / Keychain / Secret Service). */
    @PublishedApi
    internal val keyVaultIsOsBacked: Boolean get() = vaults.active.isOsBacked

    private val keyCache = ConcurrentHashMap<String, SecretKey>()

    /** Per-alias lock — avoids `intern()` pool pressure with dynamic key sets. */
    private val locks = ConcurrentHashMap<String, Any>()
    private fun lockFor(alias: String): Any = locks.computeIfAbsent(alias) { Any() }

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray {
        val secretKey = getOrCreateSecretKey(identifier)

        val iv = secureRandomBytes(GCM_IV_LENGTH)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))
        val ciphertext = cipher.doFinal(data)

        return iv + ciphertext
    }

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
        // Decrypt must NOT create a key: on orphaned ciphertext (OS-vault wipe / reinstall)
        // throw the same "No encryption key found" message Android/Apple use, so
        // KSafeCore.cleanupOrphanedCiphertext reclaims the orphan instead of minting a junk
        // key into the user's OS vault on every failed decrypt.
        val secretKey = getExistingSecretKey(identifier)

        val iv = data.copyOfRange(0, GCM_IV_LENGTH)
        val ciphertext = data.copyOfRange(GCM_IV_LENGTH, data.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH, iv))

        return cipher.doFinal(ciphertext)
    }

    override fun deleteKey(identifier: String) {
        synchronized(lockFor(identifier)) {
            keyCache.remove(identifier)
            // Remove from both active and legacy stores so a re-create after delete cannot
            // resurrect a migrated old key. Snapshot vaults.active before the try: a degrade
            // in the catch flips it to legacy and would skip the legacy-cleanup branch below,
            // exactly when that cleanup is still needed (the OS delete never happened, and a
            // stale pre-migration legacy entry may remain).
            val activeAtStart = vaults.active
            try {
                activeAtStart.delete(identifier)
            } catch (e: LinkageError) {
                // OS-vault native binding unavailable at runtime — degrade so later calls
                // don't keep paying the same penalty (see [getOrCreateSecretKey]).
                vaults.degradeToLegacy(e)
            } catch (_: Throwable) {
                // Best-effort.
            }
            if (activeAtStart !== vaults.legacy) {
                runCatching { vaults.legacy.delete(identifier) }
            }
            // Also scrub the derived-namespace location so a recreate can't resurrect the key
            // via the namespace read-fallback.
            vaults.deleteFromLegacyNamespace(identifier)
        }
    }

    /**
     * Returns the AES key for [alias], in priority order: in-memory cache, active OS-backed
     * vault, a legacy Base64 key migrated out of the DataStore file, or a freshly generated
     * one stored in the active vault.
     */
    private fun getOrCreateSecretKey(alias: String): SecretKey =
        secretKey(alias, create = true)!!

    /**
     * Decrypt-only lookup: returns the existing key or throws, never creates.
     *
     * A genuine absence on a healthy vault throws "No encryption key found" (matching
     * Android/Apple) so the orphan sweep reclaims a true orphan. A null lookup after the
     * provider has degraded is ambiguous — the key may live only in the now-unreachable OS
     * vault — so it throws "unavailable" instead, which the orphan sweep does NOT treat as
     * an orphan, leaving recoverable ciphertext intact until the OS vault returns.
     */
    private fun getExistingSecretKey(alias: String): SecretKey =
        secretKey(alias, create = false)
            ?: if (vaults.hasDegraded) {
                throw IllegalStateException(
                    "KSafe: key vault unavailable (degraded); cannot resolve key for identifier: $alias"
                )
            } else {
                throw IllegalStateException("KSafe: No encryption key found for identifier: $alias")
            }

    /**
     * Cache-checked, per-alias-locked key resolution with the runtime LinkageError degrade.
     * Returns null only when [create] is false and no key exists. The per-alias lock
     * serializes concurrent creates and is also held by [deleteKey] to block
     * cache-repopulation races.
     */
    private fun secretKey(alias: String, create: Boolean): SecretKey? {
        keyCache[alias]?.let { return it }

        return synchronized(lockFor(alias)) {
            keyCache[alias]?.let { return it }

            val key = try {
                resolveKeyVia(vaults.active, alias, create)
            } catch (e: LinkageError) {
                // Runtime native-link / class-load failure on the active OS vault (e.g. a
                // jlink JRE missing `jdk.unsupported`, so JNA throws NoClassDefFoundError on
                // first real call despite passing the construction-time self-test). Uncaught,
                // it propagates into KSafeCore.processBatch and silently drops every batch.
                // Degrade and retry on the legacy software vault so writes continue.
                vaults.degradeToLegacy(e)
                resolveKeyVia(vaults.active, alias, create)
            }

            if (key != null) keyCache[alias] = key
            key
        }
    }

    /**
     * Single attempt of the legacy-first key resolution against [active]. Caller holds
     * `lockFor(alias)` and retries on a different vault if [active] surfaces a runtime
     * native-link error. Returns null when [create] is false and no key exists.
     *
     * Legacy-first when an OS-backed vault is active: a legacy DataStore key, when present,
     * is authoritative — it provably encrypted this datastore's ciphertext. The OS vault is
     * global-per-user and long-lived, so it can hold a STALE key under the same
     * `<file>:<alias>` from a prior KSafe lifecycle (reinstall, data-clear, backup restore);
     * trusting it first would shadow the real legacy key and reset every value to default.
     * So [migrateLegacyLocked] moves an existing legacy key into the OS vault (overwriting
     * any stale entry, verifying, then scrubbing the legacy copy) and we use it; only with
     * no legacy key do we fall back to the OS vault. Migration only moves an existing key, so
     * it is safe on the decrypt (create = false) path.
     */
    private fun resolveKeyVia(active: JvmKeyVault, alias: String, create: Boolean): SecretKey? {
        val keyBytes: ByteArray? =
            if (active !== vaults.legacy) {
                // Last probe before declaring the key absent: an app upgrading from a
                // launcher-derived OS-vault namespace to the constant default finds its keys
                // only under the old derived namespace. recoverFromLegacyNamespace migrates
                // on hit; only a true miss everywhere makes "No encryption key found" (and
                // its orphan sweep) safe to report.
                migrateLegacyLocked(alias)
                    ?: active.get(alias)
                    ?: vaults.recoverFromLegacyNamespace(alias)
            } else {
                active.get(alias)
            }

        return when {
            keyBytes != null -> SecretKeySpec(keyBytes, "AES")
            !create -> null
            vaults.osVaultUnavailable -> {
                // The OS vault exists but was unreachable at construction (locked Keychain /
                // keyring not yet up), so the real key most likely lives there. Minting a
                // fresh legacy-DataStore key would be trusted as authoritative by the next
                // healthy launch's legacy-first migration, overwriting the real OS-vault key
                // and destroying everything under it. Fail closed: the ciphertext stays
                // intact and recovers once the OS store is reachable. (A genuine legacy key
                // would already have been returned above.)
                throw IllegalStateException(
                    "KSafe: OS key vault is unavailable (locked/unreachable); " +
                        "refusing to create a key for identifier: $alias to avoid " +
                        "overwriting the real OS-vault key on a later healthy " +
                        "launch. Retry once the OS store is reachable, or set " +
                        "-Dksafe.jvm.keyVault=software to use software storage."
                )
            }
            else -> {
                val keyGen = KeyGenerator.getInstance("AES")
                keyGen.init(config.keySize)
                val generated = keyGen.generateKey()
                active.put(alias, generated.encoded)
                generated
            }
        }
    }

    /**
     * Legacy → OS-vault migration for a single alias. Caller must hold `lockFor(alias)`.
     *
     * Copies the legacy DataStore key into the active OS vault, then deletes the legacy copy
     * only after re-reading and byte-verifying the OS store persisted it — a keyring that
     * silently no-ops `put()` must not destroy the only copy. Returns the legacy bytes if one
     * existed (so the current session can still use them even when the OS write couldn't be
     * finalised), else null.
     */
    private fun migrateLegacyLocked(alias: String): ByteArray? {
        val legacyBytes = vaults.legacy.get(alias) ?: return null
        try {
            vaults.active.put(alias, legacyBytes)
            if (vaults.active.get(alias)?.contentEquals(legacyBytes) == true) {
                vaults.legacy.delete(alias)
            }
        } catch (e: LinkageError) {
            // Propagate so [getOrCreateSecretKey]'s outer catch can degrade the provider and
            // retry on the legacy vault; swallowing it would keep believing the OS vault is
            // healthy while every future encrypt repeats the failure. The legacy copy is
            // intact (delete is gated on a successful read-back).
            throw e
        } catch (_: Throwable) {
            // Best-effort: a transient OS-vault hiccup must not destroy the legacy copy.
        }
        return legacyBytes
    }

    /**
     * Eager one-time sweep moving every remaining legacy `ksafe_key_*` entry out of the
     * DataStore file into the OS secret store, so a never-read-again key doesn't leave its
     * plaintext sitting in the compromisable file. Best-effort, per-alias isolated,
     * idempotent, and a no-op when there is no safer destination (software fallback /
     * opt-out). Runs on IO so the blocking per-key work doesn't tie up the caller's
     * dispatcher.
     */
    override suspend fun migrateLegacyKeysSuspend() {
        if (vaults.active === vaults.legacy || !vaults.active.isOsBacked) return
        // legacyAliases() is DataStoreKeyVault-specific; the guard above already returned on
        // the JSON-file fallback (FileKeyVault), so this cast only hits the DataStore path.
        val legacyStore = vaults.legacy as? DataStoreKeyVault ?: return
        withContext(Dispatchers.IO) {
            for (alias in legacyStore.legacyAliases()) {
                // A LinkageError is sticky for the whole engine (same JNA classloader), so a
                // degrade (which flips vaults.active === vaults.legacy) both ends this sweep
                // and routes future encrypt calls to the software vault.
                if (vaults.active === vaults.legacy) return@withContext
                try {
                    synchronized(lockFor(alias)) {
                        if (vaults.legacy.get(alias) != null) migrateLegacyLocked(alias)
                    }
                } catch (e: LinkageError) {
                    vaults.degradeToLegacy(e)
                    return@withContext
                } catch (_: Throwable) {
                    // Per-alias isolation: one bad entry can't stop the sweep.
                }
            }
        }
    }
}
