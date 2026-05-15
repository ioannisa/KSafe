package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
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
        vaultProvider ?: JvmKeyVaultProvider(dataStore)

    /** Active vault name — exposed for tests/diagnostics, not public API. */
    @PublishedApi
    internal val keyVaultName: String get() = vaults.active.name

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
            var keyBytes: ByteArray? = active.get(alias)

            // Migrate legacy plaintext key into the OS-backed vault, once.
            if (keyBytes == null && active !== vaults.legacy) {
                vaults.legacy.get(alias)?.let { legacyBytes ->
                    active.put(alias, legacyBytes)
                    runCatching { vaults.legacy.delete(alias) }
                    keyBytes = legacyBytes
                }
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
}
