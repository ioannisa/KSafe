package eu.anifantakis.lib.ksafe.internal

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import eu.anifantakis.lib.ksafe.KSafeConfig
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Web (wasmJs + js) implementation of [KSafeEncryption] using WebCrypto API via cryptography-kotlin.
 *
 * WebCrypto is async-only, so the blocking [encrypt]/[decrypt] methods from the interface
 * throw [UnsupportedOperationException]. All actual crypto work goes through the suspend
 * methods [encryptSuspend] and [decryptSuspend].
 *
 * Encryption keys are stored in localStorage as Base64-encoded raw AES key bytes,
 * using the prefix `ksafe_key_`.
 *
 * @property config Configuration for key generation (key size).
 * @property storagePrefix Prefix for localStorage keys (scoped to the KSafe instance).
 */
@PublishedApi
internal class WebSoftwareEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val storagePrefix: String = ""
) : KSafeEncryption {

    companion object {
        private const val KEY_PREFIX = "ksafe_key_"
    }

    private val provider = CryptographyProvider.Default
    private val aesGcm = provider.get(AES.GCM)

    /** In-memory cache to avoid repeated Base64 decode + key import from localStorage. */
    private val keyCache = HashMap<String, AES.GCM.Key>()

    /** Guards key generation to prevent concurrent creates overwriting each other. */
    private val keyMutex = Mutex()

    /**
     * Not supported on web — WebCrypto is async-only.
     * All encryption is routed through [encryptSuspend].
     */
    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray {
        throw UnsupportedOperationException("Web encryption is async-only. Use encryptSuspend().")
    }

    /**
     * Not supported on web — WebCrypto is async-only.
     * All decryption is routed through [decryptSuspend].
     */
    override fun decrypt(identifier: String, data: ByteArray): ByteArray {
        throw UnsupportedOperationException("Web decryption is async-only. Use decryptSuspend().")
    }

    override fun deleteKey(identifier: String) {
        val storageKey = "$storagePrefix$KEY_PREFIX$identifier"
        localStorageRemove(storageKey)
        keyCache.remove(identifier)
    }

    /**
     * Encrypts data using WebCrypto AES-GCM (suspend).
     *
     * Overrides the default delegating implementation on [KSafeEncryption]. The
     * extra parameters (`hardwareIsolated`, `requireUnlockedDevice`) don't map
     * to anything in WebCrypto so they are accepted and ignored.
     */
    @OptIn(ExperimentalEncodingApi::class)
    override suspend fun encryptSuspend(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
    ): ByteArray {
        val key = getOrCreateKey(identifier)
        val cipher = key.cipher()
        return cipher.encrypt(data)
    }

    /**
     * Decrypts data using WebCrypto AES-GCM (suspend).
     */
    @OptIn(ExperimentalEncodingApi::class)
    override suspend fun decryptSuspend(identifier: String, data: ByteArray): ByteArray {
        val key = getOrCreateKey(identifier)
        val cipher = key.cipher()
        return cipher.decrypt(data)
    }

    /**
     * Gets an existing key from localStorage or creates a new one.
     *
     * Uses a Mutex to prevent concurrent key generation from overwriting
     * a just-created key (race condition when multiple putEncrypted calls
     * run in parallel for the same alias).
     *
     * Keys are cached in memory after first access.
     */
    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun getOrCreateKey(alias: String): AES.GCM.Key {
        // Fast path: memory cache (no lock needed, web is single-threaded
        // but the mutex protects across suspend points)
        keyCache[alias]?.let { return it }

        return keyMutex.withLock {
            // Double-check after acquiring lock
            keyCache[alias]?.let { return it }

            val storageKey = "$storagePrefix$KEY_PREFIX$alias"
            val existing = localStorageGet(storageKey)

            val key = if (existing != null) {
                val keyBytes = Base64.decode(existing)
                aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, keyBytes)
            } else {
                // Generate new key
                val keySize = when (config.keySize) {
                    128 -> AES.Key.Size.B128
                    else -> AES.Key.Size.B256
                }
                val newKey = aesGcm.keyGenerator(keySize).generateKey()

                // Store in localStorage
                val keyBytes = newKey.encodeToByteArray(AES.Key.Format.RAW)
                localStorageSet(storageKey, Base64.encode(keyBytes))
                newKey
            }

            keyCache[alias] = key
            key
        }
    }
}
