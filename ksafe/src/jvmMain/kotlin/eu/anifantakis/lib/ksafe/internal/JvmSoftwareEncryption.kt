package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.KSafeConfig
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
    dataStore: DataStore<Preferences>,
    /** Test seam: inject a vault provider and bypass OS detection. */
    vaultProvider: JvmKeyVaultProvider? = null,
) : KSafeEncryption {

    companion object {
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
    }

    private val vaults: JvmKeyVaultProvider =
        vaultProvider ?: JvmKeyVaultProvider(
            dataStore,
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
        val secretKey = getOrCreateSecretKey(identifier)

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
            runCatching { vaults.active.delete(identifier) }
            if (vaults.active !== vaults.legacy) {
                runCatching { vaults.legacy.delete(identifier) }
            }
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
    private fun getOrCreateSecretKey(alias: String): SecretKey {
        keyCache[alias]?.let { return it }

        return synchronized(lockFor(alias)) {
            keyCache[alias]?.let { return it }

            val active = vaults.active

            // Legacy-first when an OS-backed vault is active.
            //
            // The legacy DataStore key, WHEN PRESENT, is authoritative: it
            // provably encrypted this datastore's on-disk ciphertext. The OS
            // vault (Keychain / DPAPI / Secret Service) is global-per-user and
            // long-lived — it can hold a STALE key under the same
            // `<file>:<alias>` from a prior KSafe lifecycle (reinstall,
            // data-clear, backup restore, mixed 2.0/2.1 runs). The old code
            // trusted the OS vault first and migrated only when it was empty,
            // so a stale OS key shadowed the real legacy key: every encrypted
            // value failed to decrypt and silently reset to its default
            // (plaintext values, needing no key, survived). See the 2.0.0→
            // 2.1.0 data-loss regression.
            //
            // So: if a legacy key exists, migrate it now —
            // [migrateLegacyLocked] overwrites any stale OS-vault entry,
            // re-reads to verify, then scrubs the legacy copy — and use it.
            // Only fall back to the OS vault when there is NO legacy key
            // (already migrated and scrubbed, or a genuinely fresh alias).
            var keyBytes: ByteArray? =
                if (active !== vaults.legacy) {
                    migrateLegacyLocked(alias) ?: active.get(alias)
                } else {
                    active.get(alias)
                }

            val key: SecretKey = if (keyBytes != null) {
                SecretKeySpec(keyBytes, "AES")
            } else {
                val keyGen = KeyGenerator.getInstance("AES")
                keyGen.init(config.keySize)
                val generated = keyGen.generateKey()
                active.put(alias, generated.encoded)
                generated
            }

            keyCache[alias] = key
            key
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
        runCatching {
            vaults.active.put(alias, legacyBytes)
            if (vaults.active.get(alias)?.contentEquals(legacyBytes) == true) {
                vaults.legacy.delete(alias)
            }
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
        val active = vaults.active
        if (active === vaults.legacy || !active.isOsBacked) return
        withContext(Dispatchers.IO) {
            for (alias in vaults.legacy.legacyAliases()) {
                runCatching {
                    synchronized(lockFor(alias)) {
                        if (vaults.legacy.get(alias) != null) migrateLegacyLocked(alias)
                    }
                }
            }
        }
    }
}
