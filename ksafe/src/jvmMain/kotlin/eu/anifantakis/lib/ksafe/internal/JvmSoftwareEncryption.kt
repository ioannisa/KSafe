package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStoreKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.keyvault.legacyResolvedJvmAppNamespace
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
 * JVM [KSafeEncryption]: software AES-GCM (`javax.crypto`) for the payload, with the
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
    dataStore: DataStore<Preferences>? = null,
    vaultProvider: JvmKeyVaultProvider? = null,
) : KSafeEncryption {

    companion object {
        /** Suffix marking a custody-marker slot; must never be treated as a key alias. */
        private const val FALLBACK_MINT_MARKER_SUFFIX = ".${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}"
    }

    private val vaults: JvmKeyVaultProvider =
        vaultProvider ?: JvmKeyVaultProvider(
            requireNotNull(dataStore) {
                "JvmSoftwareEncryption requires a dataStore unless a vaultProvider is provided"
            },
            resolveJvmAppNamespace(config.appNamespace),
            legacyAppNamespace = legacyResolvedJvmAppNamespace(config.appNamespace),
        )

    @PublishedApi
    internal val keyVaultName: String get() = vaults.active.name

    @PublishedApi
    internal val keyVaultIsOsBacked: Boolean get() = vaults.active.isOsBacked

    /**
     * True when an OS vault exists but failed its construction self-test, so KSafe refuses to
     * mint keys and every encrypted create (and any OS-resident read) throws until it is
     * reachable — the degraded, NON-operational state (distinct from "no OS vault → software
     * works"). Surfaced so `protectionInfo` can report it as non-operational.
     */
    @PublishedApi
    internal val osVaultUnavailable: Boolean get() = vaults.osVaultUnavailable

    /** A cached key tagged with the purge epoch it was resolved under (see [cacheEpoch]). */
    private class CachedKey(val key: SecretKey, val epoch: Long)

    private val keyCache = ConcurrentHashMap<String, CachedKey>()

    private val aliasLocks = AliasLocks()

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        // Bounded retry around a sibling-instance clearAll racing this encrypt: the key was
        // resolved, then the wipe landed, and without the epoch re-check the acknowledged
        // ciphertext would be unreadable on the next launch. The response is to RE-ENCRYPT
        // under whatever legitimately owns the vault slot afterwards — a concurrent winner's
        // key, or fresh material minted by the next resolution. The key this attempt used is
        // never re-persisted: it is exactly the material `clearAll()` promised to destroy,
        // and re-inserting it would make a pre-wipe backup of the store decryptable again.
        repeat(2) {
            val epochAtResolve = cacheEpoch.get()
            val secretKey = getOrCreateSecretKey(identifier)
            val out = encryptWith(secretKey, data, aad)
            if (cacheEpoch.get() == epochAtResolve) return out
            synchronized(aliasLocks.forAlias(identifier)) {
                val vaultBytes = runCatching { vaults.active.get(identifier) }.getOrNull()
                // Our key still owns the slot (e.g. a concurrent re-mint of identical bytes) —
                // the ciphertext is readable exactly as persisted, keep it.
                if (vaultBytes != null && vaultBytes.contentEquals(secretKey.encoded)) return out
                // Slot wiped, or a different key won it — fall through and re-encrypt.
            }
        }
        // Two consecutive wipes raced this write; seal under the current resolution and stop
        // re-checking. The pathological tail fails toward erasure — the ciphertext may land
        // under a key a third wipe then destroys — never toward undoing a wipe.
        return encryptWith(getOrCreateSecretKey(identifier), data, aad)
    }

    private fun encryptWith(secretKey: SecretKey, data: ByteArray, aad: ByteArray?): ByteArray {
        val iv = secureRandomBytes(JvmAesGcm.IV_LENGTH_BYTES)
        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(JvmAesGcm.TAG_LENGTH_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return iv + cipher.doFinal(data)
    }

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray {
        // Fail-closed: decrypt must NOT create a key. Orphaned ciphertext throws the same
        // "No encryption key found" as Android/Apple so the orphan sweep reclaims it instead
        // of minting a junk key into the OS vault on every failed decrypt.
        val secretKey = getExistingSecretKey(identifier)

        val iv = data.copyOfRange(0, JvmAesGcm.IV_LENGTH_BYTES)
        val ciphertext = data.copyOfRange(JvmAesGcm.IV_LENGTH_BYTES, data.size)

        val cipher = Cipher.getInstance(JvmAesGcm.TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(JvmAesGcm.TAG_LENGTH_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)

        return cipher.doFinal(ciphertext)
    }

    /**
     * Purge epoch, bumped by [onStoreCleared]. Each cache entry is tagged with the epoch it was
     * resolved under and served only while its tag equals the current epoch, so a `clearAll`
     * invalidates every cached key — including one a concurrent reader inserts AFTER the purge
     * with a pre-purge tag. Without this a stale cached key (whose record `clearAll` already
     * wiped from the DataStore) would be served on a later encrypt and never re-persisted:
     * readable all session, unreadable after the next launch.
     */
    private val cacheEpoch = java.util.concurrent.atomic.AtomicLong(0)

    private fun cachedKey(alias: String): SecretKey? =
        keyCache[alias]?.takeIf { it.epoch == cacheEpoch.get() }?.key

    override fun onStoreCleared() {
        cacheEpoch.incrementAndGet()
        keyCache.clear()
        // Runs on the write consumer (via performClearAll), not the caller thread, so it can't
        // race a concurrent write's key mint and strand an acknowledged encrypted value.
        runCatching { vaults.active.clearAll() }
        if (vaults.legacy !== vaults.active) runCatching { vaults.legacy.clearAll() }
    }

    override fun deleteKey(identifier: String) {
        synchronized(aliasLocks.forAlias(identifier)) {
            keyCache.remove(identifier)
            // Snapshot vaults.active before the try: a degrade in the catch flips it to legacy
            // and would skip the legacy-cleanup branch below, exactly when it is still needed
            // (the OS delete never happened, a stale pre-migration legacy entry may remain).
            val activeAtStart = vaults.active
            try {
                activeAtStart.delete(identifier)
            } catch (e: LinkageError) {
                vaults.degradeToLegacy(e)
            } catch (_: Throwable) {
            }
            if (activeAtStart !== vaults.legacy) {
                runCatching { vaults.legacy.delete(identifier) }
            }
            // Scrub the derived-namespace location too, else a recreate resurrects the key via
            // the namespace read-fallback.
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
     * Resolve/create only — no throwaway encrypt, and none of the encrypt path's clearAll-race
     * handling: prewarm output is discarded, so there is no acknowledged ciphertext whose
     * readability a raced wipe could break, and nothing that needs re-encrypting.
     */
    override suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ) {
        getOrCreateSecretKey(identifier)
    }

    /**
     * Decrypt-only lookup: returns the existing key or throws, never creates.
     *
     * Genuine absence on a healthy vault throws "No encryption key found" so the orphan sweep
     * reclaims it. A null after the provider degraded is ambiguous (the key may live only in
     * the now-unreachable OS vault), so it throws "unavailable" — which the sweep does NOT
     * treat as an orphan, leaving recoverable ciphertext intact until the OS vault returns.
     */
    private fun getExistingSecretKey(alias: String): SecretKey =
        secretKey(alias, create = false)
            ?: if (vaults.hasDegraded) {
                throw IllegalStateException(
                    "KSafe: key ${KSafeEngineMessage.VAULT_UNAVAILABLE} (degraded); cannot resolve key for identifier: $alias"
                )
            } else {
                throw IllegalStateException(KSafeEngineMessage.noKeyFound(alias))
            }

    /**
     * Cache-checked, per-alias-locked key resolution with the runtime LinkageError degrade.
     * Returns null only when [create] is false and no key exists. The per-alias lock is also
     * held by [deleteKey] to block cache-repopulation races.
     */
    private fun secretKey(alias: String, create: Boolean): SecretKey? {
        cachedKey(alias)?.let { return it }

        return synchronized(aliasLocks.forAlias(alias)) {
            cachedKey(alias)?.let { return it }
            // Captured BEFORE the vault read: the cached entry is stamped with this epoch, so a
            // purge landing during or after the read leaves the entry tagged stale and it is
            // never served again.
            val epochAtRead = cacheEpoch.get()

            val key = try {
                resolveKeyVia(vaults.active, alias, create)
            } catch (e: LinkageError) {
                // Runtime native-link failure on the OS vault (e.g. a jlink JRE missing
                // `jdk.unsupported`, so JNA throws NoClassDefFoundError on first real call
                // despite passing the construction-time self-test). Degrade and retry on the
                // legacy software vault so writes continue instead of silently dropping.
                vaults.degradeToLegacy(e)
                resolveKeyVia(vaults.active, alias, create)
            }

            if (key != null) keyCache[alias] = CachedKey(key, epochAtRead)
            key
        }
    }

    /**
     * Single attempt of the legacy-first key resolution against [active]. Caller holds
     * `aliasLocks.forAlias(alias)`. Returns null when [create] is false and no key exists.
     *
     * Legacy-first when an OS-backed vault is active: a legacy DataStore key, when present, is
     * authoritative — it provably encrypted this datastore's ciphertext. The OS vault is
     * global-per-user and long-lived, so it can hold a STALE key under the same
     * `<file>:<alias>` from a prior KSafe lifecycle (reinstall, data-clear, backup restore);
     * trusting it first would shadow the real legacy key and reset every value to default. So
     * [migrateLegacyLocked] moves an existing legacy key into the OS vault (overwrite, verify,
     * scrub the legacy copy) and we use it; only with no legacy key do we fall back to the OS
     * vault. Migration only moves an existing key, so it is safe on the decrypt path.
     */
    private fun resolveKeyVia(active: JvmKeyVault, alias: String, create: Boolean): SecretKey? {
        val keyBytes: ByteArray? =
            if (active !== vaults.legacy) {
                // Last probe before declaring the key absent: an app upgrading from a
                // launcher-derived OS-vault namespace to the constant default finds its keys
                // only under the old derived namespace. recoverFromLegacyNamespace migrates on
                // hit; only a true miss everywhere makes "No encryption key found" safe.
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
                // Fail-closed: the OS vault was unreachable at construction (locked Keychain /
                // keyring not yet up), so the real key most likely lives there. Minting a fresh
                // legacy-DataStore key would be trusted as authoritative by the next healthy
                // launch's legacy-first migration, overwriting the real OS-vault key and
                // destroying everything under it. The ciphertext recovers once the OS store is
                // reachable. (A genuine legacy key would already have been returned above.)
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
                keyGen.init(config.aesKeySize.bits)
                val generated = keyGen.generateKey()
                active.put(alias, generated.encoded)
                // Custody marker: a key WE mint into the legacy/software slot (opt-out
                // session, runtime vault degrade, vault-less host) is fallback-minted —
                // genuine pre-2.x legacy keys never carry it. The legacy-first migration
                // uses it to tell "authoritative legacy key, replace a stale OS copy"
                // from "fallback key that must never overwrite the live OS key".
                if (active === vaults.legacy) {
                    runCatching { vaults.legacy.put(fallbackMintMarker(alias), FALLBACK_MINT_MARKER) }
                }
                generated
            }
        }
    }

    /**
     * Legacy → OS-vault migration for a single alias. Caller must hold `aliasLocks.forAlias(alias)`.
     *
     * Copies the legacy DataStore key into the active OS vault, then deletes the legacy copy
     * only after re-reading and byte-verifying the OS store persisted it — a keyring that
     * silently no-ops `put()` must not destroy the only copy. Returns the legacy bytes if one
     * existed (so the session can still use them even when the OS write couldn't finalise),
     * else null.
     */
    private fun migrateLegacyLocked(alias: String): ByteArray? {
        // A custody marker is local-custody bookkeeping, never key material: migrating one into
        // the OS vault would delete it from the legacy slot, and the conflict guard below —
        // which reads the marker from the LEGACY vault — would then see none and let the
        // fallback key overwrite the live OS key it exists to protect.
        if (isFallbackMintMarker(alias)) return null
        val legacyBytes = vaults.legacy.get(alias) ?: return null
        try {
            // A FALLBACK-MINTED legacy key must NEVER overwrite a different live OS-vault
            // key: a `-Dksafe.jvm.keyVault=software` session (or a runtime LinkageError
            // degrade) mints fresh keys into the legacy slot while the real key lives in
            // the OS vault — blindly migrating would destroy it and every value under it,
            // with no user write needed (prewarm suffices). On that conflict keep BOTH:
            // this session keeps reading with the legacy key (unchanged visible behavior),
            // the OS key survives for recovery, and a loud warning asks the developer to
            // resolve. A GENUINE pre-2.x legacy key (no custody marker — old binaries
            // never wrote one) stays authoritative and still replaces a stale OS copy,
            // preserving the reinstall/data-clear fix. Equal bytes re-migrate idempotently.
            val existing = vaults.active.get(alias)
            val fallbackMinted = vaults.legacy.get(fallbackMintMarker(alias)) != null
            if (fallbackMinted && existing != null && !existing.contentEquals(legacyBytes)) {
                legacyConflictWarning.warn {
                    "KSafe SECURITY WARNING: the OS key vault and the local key file " +
                        "both hold a (different) key for '$alias'. This usually means " +
                        "a software-fallback session (-Dksafe.jvm.keyVault=software or " +
                        "a runtime vault degrade) minted new keys while the OS vault " +
                        "held live ones. KSafe keeps BOTH keys and continues with the " +
                        "local one; values encrypted under the OS key stay recoverable. " +
                        "Resolve by re-writing wanted values (or deleting the stale " +
                        "local key file after verifying your data reads correctly)."
                }
                return legacyBytes
            }
            vaults.active.put(alias, legacyBytes)
            if (vaults.active.get(alias)?.contentEquals(legacyBytes) == true) {
                vaults.legacy.delete(alias)
                vaults.legacy.delete(fallbackMintMarker(alias))
            }
        } catch (e: LinkageError) {
            // Propagate so the outer catch can degrade and retry on the legacy vault; the
            // legacy copy is intact (delete is gated on a successful read-back).
            throw e
        } catch (_: Throwable) {
            // Best-effort: a transient OS-vault hiccup must not destroy the legacy copy.
        }
        return legacyBytes
    }

    /** One warning per engine for the both-vaults-hold-different-keys conflict. */
    private val legacyConflictWarning = OneShotWarning()

    /** Custody-marker record for a key WE minted into the legacy/software slot. */
    private fun fallbackMintMarker(alias: String) = "$alias$FALLBACK_MINT_MARKER_SUFFIX"

    /** True for a custody-marker slot rather than a real key alias. */
    private fun isFallbackMintMarker(alias: String) = alias.endsWith(FALLBACK_MINT_MARKER_SUFFIX)

    private val FALLBACK_MINT_MARKER = byteArrayOf(1)


    /**
     * Eager one-time sweep moving every remaining legacy `ksafe_key_*` entry out of the
     * DataStore file into the OS secret store, so a never-read-again key doesn't leave its
     * plaintext sitting in the compromisable file. Best-effort, per-alias isolated, and a
     * no-op when there is no safer destination (software fallback / opt-out).
     */
    override suspend fun migrateLegacyKeysSuspend() {
        if (vaults.active === vaults.legacy || !vaults.active.isOsBacked) return
        val legacyStore = vaults.legacy as? DataStoreKeyVault ?: return
        withContext(Dispatchers.IO) {
            for (alias in legacyStore.legacyAliases()) {
                // A LinkageError is sticky for the whole engine (same JNA classloader), so a
                // degrade (which flips vaults.active === vaults.legacy) both ends this sweep
                // and routes future encrypt calls to the software vault.
                if (vaults.active === vaults.legacy) return@withContext
                try {
                    synchronized(aliasLocks.forAlias(alias)) {
                        if (vaults.legacy.get(alias) != null) migrateLegacyLocked(alias)
                    }
                } catch (e: LinkageError) {
                    vaults.degradeToLegacy(e)
                    return@withContext
                } catch (_: Throwable) {
                }
            }
        }
    }
}
