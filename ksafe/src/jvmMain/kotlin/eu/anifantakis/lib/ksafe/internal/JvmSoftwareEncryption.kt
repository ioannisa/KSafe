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
 * JVM implementation of [KSafeEncryption] using software AES-256-GCM
 * (`javax.crypto`) for the payload, with the **AES key itself protected by an
 * OS secret store** via [JvmKeyVault]:
 *
 * - Windows → DPAPI (key wrapped with the user's login credentials)
 * - macOS → login Keychain (SE-gated on Apple Silicon / T2)
 * - Linux → Secret Service / libsecret (login keyring)
 *
 * When no OS store is reachable (headless Linux without a keyring, JNA link
 * failure, …) [JvmKeyVaultProvider] transparently falls back to the legacy
 * Base64-in-DataStore scheme and logs a one-time security warning. Existing
 * keys written by KSafe ≤ 2.0 are **migrated on first read**: copied into the
 * OS store, then removed from the DataStore file.
 *
 * The crypto (AES-256-GCM, random 12-byte IV, IV‖ciphertext layout) is
 * unchanged, so data encrypted by previous versions still decrypts after the
 * key migrates.
 *
 * @property config Key-generation configuration (key size).
 * @property dataStore DataStore used by the legacy/fallback vault and the
 *   Windows DPAPI vault (for the wrapped — and therefore safe-at-rest — blob).
 */
@PublishedApi
internal class JvmSoftwareEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    /**
     * Nullable for the no-DataStore JSON-file fallback path: there a
     * [vaultProvider] (file-backed) is supplied instead.
     */
    dataStore: DataStore<Preferences>? = null,
    /** Test seam / fallback wiring: inject a vault provider and bypass OS detection. */
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

    /**
     * True iff the active vault is OS-backed (DPAPI / Keychain / Secret
     * Service). False when fallback or opt-out selected [vaults.legacy].
     * Used by the JVM `KSafe` factory to populate `KSafeProtectionInfo`.
     */
    @PublishedApi
    internal val keyVaultIsOsBacked: Boolean get() = vaults.active.isOsBacked

    /** In-memory cache to avoid repeated vault round-trips. */
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

        // IV prepended to ciphertext.
        return iv + ciphertext
    }

    override fun decrypt(identifier: String, data: ByteArray): ByteArray {
        // Decrypt must NOT create a key. If the key is gone (orphaned
        // ciphertext after an OS-vault wipe / reinstall), throw the same
        // "No encryption key found" message Android and Apple use, so
        // KSafeCore.cleanupOrphanedCiphertext reclaims the JVM orphan too —
        // and so we don't mint a spurious junk key into the user's OS vault
        // on every failed decrypt (which getOrCreateSecretKey would do).
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
            // Remove from both the active store and the legacy store so a
            // re-create after delete cannot resurrect a migrated old key.
            // A LinkageError here means the OS vault's native binding is
            // unavailable at runtime — degrade so subsequent encrypt/decrypt
            // calls don't keep paying the same penalty (see
            // [getOrCreateSecretKey]).
            //
            // Snapshot vaults.active BEFORE the try: a degrade inside the
            // catch flips vaults.active to legacy, which would otherwise
            // skip the legacy-cleanup branch below — even though that's
            // exactly when the legacy cleanup is still needed (we never
            // managed to delete from the OS vault, and there may be a
            // stale legacy entry from before migration).
            val activeAtStart = vaults.active
            try {
                activeAtStart.delete(identifier)
            } catch (e: LinkageError) {
                vaults.degradeToLegacy(e)
            } catch (_: Throwable) {
                // Best-effort: swallow other failures on delete.
            }
            if (activeAtStart !== vaults.legacy) {
                runCatching { vaults.legacy.delete(identifier) }
            }
            // Also scrub the 2.1.0/2.1.1 derived-namespace location, so a
            // recreate after delete can't resurrect the pre-upgrade key via
            // the namespace read-fallback.
            vaults.deleteFromLegacyNamespace(identifier)
        }
    }

    /**
     * Returns the AES key for [alias], in priority order:
     * 1. in-memory cache,
     * 2. the active OS-backed vault,
     * 3. migration: a legacy Base64 key in the DataStore file — copied into
     *    the active vault and then deleted from the file,
     * 4. freshly generated and stored in the active vault.
     *
     * Per-alias `synchronized` prevents two concurrent creates from racing
     * (and is also held by [deleteKey] to block cache-repopulation races).
     */
    private fun getOrCreateSecretKey(alias: String): SecretKey =
        // create = true never returns null.
        secretKey(alias, create = true)!!

    /**
     * Decrypt-only lookup: returns the existing key, or throws. NEVER creates.
     *
     * When the vault is healthy and the key is genuinely absent it throws the
     * same "No encryption key found" message Android/Apple use, so the orphan
     * sweep can reclaim a true JVM orphan and we never mint a junk key on a
     * failed decrypt. When the provider has degraded (a runtime OS-vault
     * failure forced the software fallback) a null lookup is ambiguous — the
     * key may live only in the now-unreachable OS vault — so it throws an
     * "unavailable" message the orphan sweep does NOT treat as an orphan,
     * leaving recoverable ciphertext intact until the OS vault is reachable.
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
     * Cache-checked, per-alias-locked key resolution with the runtime
     * LinkageError degrade. Returns null only when [create] is false and no
     * key exists.
     *
     * Per-alias `synchronized` prevents two concurrent creates from racing
     * (and is also held by [deleteKey] to block cache-repopulation races).
     */
    private fun secretKey(alias: String, create: Boolean): SecretKey? {
        keyCache[alias]?.let { return it }

        return synchronized(lockFor(alias)) {
            keyCache[alias]?.let { return it }

            val key = try {
                resolveKeyVia(vaults.active, alias, create)
            } catch (e: LinkageError) {
                // Runtime native-link / class-load failure on the active OS
                // vault. Canonical case: a jlink-built JRE missing
                // `jdk.unsupported`, so JNA throws `NoClassDefFoundError:
                // sun/misc/Unsafe` on first real call even though the
                // construction-time self-test passed. Left uncaught this
                // propagates into KSafeCore.processBatch and silently drops
                // every batch. Degrade the provider and retry on the legacy
                // software vault so writes continue.
                vaults.degradeToLegacy(e)
                resolveKeyVia(vaults.active, alias, create)
            }

            if (key != null) keyCache[alias] = key
            key
        }
    }

    /**
     * Single attempt of the legacy-first key resolution against [active].
     * Caller holds `lockFor(alias)` and is responsible for retrying on a
     * different vault if [active] surfaces a runtime native-link error.
     * Returns null when [create] is false and no key exists.
     *
     * Legacy-first when an OS-backed vault is active: the legacy DataStore
     * key, WHEN PRESENT, is authoritative — it provably encrypted this
     * datastore's on-disk ciphertext. The OS vault (Keychain / DPAPI / Secret
     * Service) is global-per-user and long-lived, so it can hold a STALE key
     * under the same `<file>:<alias>` from a prior KSafe lifecycle (reinstall,
     * data-clear, backup restore). Trusting the OS vault first would let that
     * stale key shadow the real legacy key and silently reset every encrypted
     * value to its default.
     *
     * So: if a legacy key exists, migrate it now — [migrateLegacyLocked]
     * overwrites any stale OS-vault entry, re-reads to verify, then scrubs
     * the legacy copy — and use it. Only fall back to the OS vault when
     * there is NO legacy key. Migration only ever moves an *existing* key,
     * so it is safe on the decrypt (create = false) path.
     */
    private fun resolveKeyVia(active: JvmKeyVault, alias: String, create: Boolean): SecretKey? {
        val keyBytes: ByteArray? =
            if (active !== vaults.legacy) {
                // Last probe before declaring the key absent: released
                // 2.1.0/2.1.1 derived the OS-vault namespace from the launcher,
                // so an app upgrading to the constant default namespace finds
                // its real keys only under the OLD derived namespace.
                // recoverFromLegacyNamespace migrates on hit; only a true miss
                // everywhere makes "No encryption key found" (and the orphan
                // sweep it triggers) safe to report.
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
                // An OS vault exists for this platform but was unreachable at
                // construction (locked Keychain / login keyring not yet up), so
                // the real key for this alias most likely lives there. Minting
                // a fresh key into the legacy DataStore would be trusted as
                // authoritative by the next healthy launch's legacy-first
                // migration, overwriting the real OS-vault key and destroying
                // everything encrypted under it. Fail closed instead: the
                // on-disk ciphertext stays intact and recovers once the OS
                // store is reachable. (A genuine legacy key for this alias
                // would already have been returned above via `keyBytes`.)
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
     * Hardened legacy → OS-vault migration for a single alias.
     * **Caller must hold `lockFor(alias)`.**
     *
     * Copies the legacy DataStore key into the active OS vault, then removes
     * it from the file **only after re-reading and byte-verifying** the OS
     * store actually persisted it — a buggy/again-unavailable keyring that
     * silently no-ops `put()` must not destroy the only copy. Returns the
     * legacy key bytes if one existed (so the lazy path can still use it for
     * the current session even when the OS write couldn't be finalised),
     * else null.
     */
    private fun migrateLegacyLocked(alias: String): ByteArray? {
        val legacyBytes = vaults.legacy.get(alias) ?: return null
        try {
            vaults.active.put(alias, legacyBytes)
            if (vaults.active.get(alias)?.contentEquals(legacyBytes) == true) {
                vaults.legacy.delete(alias)
            }
        } catch (e: LinkageError) {
            // Runtime native-link / class-load failure — let it propagate so
            // [getOrCreateSecretKey]'s outer catch can degrade the provider
            // and retry on the legacy vault. Swallowing this here would mean
            // we silently keep believing the OS vault is healthy while every
            // future encrypt repeats the same failure. The legacy copy is
            // intact (the delete above is gated on a successful read-back).
            throw e
        } catch (_: Throwable) {
            // Best-effort: a transient OS-vault hiccup must not destroy the
            // legacy copy. The read-back gate already protects against a
            // silently-no-op put; this also tolerates exceptions from put/get.
        }
        return legacyBytes
    }

    /**
     * Eager one-time sweep: move **every** remaining legacy `ksafe_key_*`
     * entry out of the DataStore file into the OS secret store, so a key
     * that is never read again doesn't keep its plaintext sitting in the
     * compromisable file indefinitely. Best-effort and per-alias isolated
     * (one bad entry can't stop the sweep), idempotent, and a **no-op when
     * there is no safer destination** (software fallback / opt-out). Runs on
     * IO so the (blocking, JNA/DataStore) per-key work doesn't tie up the
     * caller's coroutine dispatcher.
     */
    override suspend fun migrateLegacyKeysSuspend() {
        if (vaults.active === vaults.legacy || !vaults.active.isOsBacked) return
        // legacyAliases() is DataStoreKeyVault-specific (the migration source).
        // In the JSON-file fallback the legacy vault is a FileKeyVault and the
        // guard above already returned (active === legacy, !isOsBacked), so this
        // cast is only ever reached on the DataStore path.
        val legacyStore = vaults.legacy as? DataStoreKeyVault ?: return
        withContext(Dispatchers.IO) {
            for (alias in legacyStore.legacyAliases()) {
                // A LinkageError on any one alias is sticky for the whole
                // engine (same JNA classloader), so stop the sweep instead of
                // grinding through every alias. degradeToLegacy flips
                // vaults.active === vaults.legacy, which both ends the sweep
                // here and routes future encrypt calls to the software vault.
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
