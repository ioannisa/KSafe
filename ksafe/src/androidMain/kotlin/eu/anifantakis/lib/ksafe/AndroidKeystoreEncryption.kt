package eu.anifantakis.lib.ksafe

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android implementation of [KSafeEncryption] using the Android Keystore System.
 *
 * This provides hardware-backed encryption where available, with keys that are:
 * - Non-exportable (cannot be extracted from the device)
 * - Bound to the application
 * - Automatically deleted on app uninstall
 *
 * @property config Configuration for key generation (key size)
 */
@PublishedApi
internal class AndroidKeystoreEncryption(
    private val config: KSafeConfig = KSafeConfig()
) : KSafeEncryption {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
    }

    /**
     * Thread-safe cache for SecretKey objects to avoid repeated Keystore lookups.
     * Keys are cached after first access and remain valid until explicitly deleted.
     */
    private val keyCache = java.util.concurrent.ConcurrentHashMap<String, SecretKey>()

    /** Per-alias lock objects — avoids `intern()` pool pressure with dynamic key sets. */
    private val locks = java.util.concurrent.ConcurrentHashMap<String, Any>()
    private fun lockFor(alias: String): Any = locks.computeIfAbsent(alias) { Any() }

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray {
        return try {
            encryptWithKey(identifier, data, hardwareIsolated, requireUnlockedDevice)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Key was invalidated (e.g., device security settings changed)
            // Delete the old key and create a new one
            deleteKeyInternal(identifier)
            encryptWithKey(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }
    }

    private fun encryptWithKey(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray {
        val secretKey = getOrCreateSecretKey(identifier, hardwareIsolated, requireUnlockedDevice)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        } catch (e: java.security.InvalidKeyException) {
            throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked.", e)
        }

        val iv = cipher.iv
        val ciphertext = cipher.doFinal(data)

        // Return IV prepended to ciphertext
        return iv + ciphertext
    }

    override fun decrypt(identifier: String, data: ByteArray): ByteArray {
        return try {
            decryptWithKey(identifier, data)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Key was invalidated - the encrypted data cannot be recovered
            // Delete the invalid key so future encryptions can work
            deleteKeyInternal(identifier)
            // Re-throw to let caller handle (will return default value)
            throw e
        }
    }

    private fun decryptWithKey(identifier: String, data: ByteArray): ByteArray {
        // Key was created with its accessibility setting - just retrieve it
        val secretKey = getExistingSecretKey(identifier)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        // Extract IV (first 12 bytes) and ciphertext
        val iv = data.sliceArray(0 until GCM_IV_LENGTH)
        val ciphertext = data.sliceArray(GCM_IV_LENGTH until data.size)

        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        } catch (e: java.security.InvalidKeyException) {
            throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked.", e)
        }

        return cipher.doFinal(ciphertext)
    }

    override fun deleteKey(identifier: String) {
        deleteKeyInternal(identifier)
    }

    private fun deleteKeyInternal(identifier: String) {
        synchronized(lockFor(identifier)) {
            keyCache.remove(identifier)

            try {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                if (keyStore.containsAlias(identifier)) {
                    keyStore.deleteEntry(identifier)
                }
            } catch (_: Exception) {
                // Silently ignore - key may not exist or keystore may be unavailable
            }
        }
    }

    /**
     * Gets an existing key from the Keystore (for decryption).
     * Does not create a new key - if the key doesn't exist, throws an exception.
     *
     * @param identifier The key identifier/alias
     * @throws IllegalStateException if the key doesn't exist
     */
    private fun getExistingSecretKey(identifier: String): SecretKey {
        // Fast path: return cached key
        keyCache[identifier]?.let { return it }

        // Slow path: load from Keystore
        synchronized(lockFor(identifier)) {
            // Double-check after acquiring lock
            keyCache[identifier]?.let { return it }

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

            if (!keyStore.containsAlias(identifier)) {
                throw IllegalStateException("KSafe: No encryption key found for identifier: $identifier")
            }

            val key = keyStore.getKey(identifier, null) as SecretKey
            keyCache[identifier] = key
            return key
        }
    }

    /**
     * Generates a new AES key in the Android Keystore.
     *
     * When [hardwareIsolated] is true, attempts to generate the key in StrongBox hardware
     * (a physically separate security chip). If StrongBox is unavailable on the device,
     * falls back to the TEE (Trusted Execution Environment) automatically.
     *
     * @param identifier The key alias in the Keystore
     * @param hardwareIsolated Whether to attempt StrongBox key generation
     */
    private fun generateNewKey(
        identifier: String,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val builder = KeyGenParameterSpec.Builder(
            identifier,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(config.keySize)

        val resolvedRequireUnlockedDevice = requireUnlockedDevice ?: config.requireUnlockedDevice
        if (resolvedRequireUnlockedDevice && android.os.Build.VERSION.SDK_INT >= 28) {
            builder.setUnlockedDeviceRequired(true)
        }

        // StrongBox: physically separate security chip (API 28+)
        // Falls back to TEE if the device doesn't have StrongBox hardware
        if (hardwareIsolated && android.os.Build.VERSION.SDK_INT >= 28) {
            builder.setIsStrongBoxBacked(true)
            return try {
                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
            } catch (e: StrongBoxUnavailableException) {
                // Device doesn't have StrongBox — fall back to TEE
                builder.setIsStrongBoxBacked(false)
                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
            }
        }

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    /**
     * Gets an existing key from the Keystore or creates a new one if it doesn't exist.
     * Uses in-memory cache to avoid repeated Keystore lookups.
     *
     * Key generation parameters:
     * - Algorithm: AES
     * - Block Mode: GCM (hardcoded for security)
     * - Padding: None (hardcoded for security)
     * - Key Size: Configurable via [KSafeConfig.keySize]
     *
     * @param identifier The key identifier/alias
     * @param hardwareIsolated Whether to attempt StrongBox key generation for new keys
     */
    private fun getOrCreateSecretKey(
        identifier: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null
    ): SecretKey {
        // Fast path: return cached key
        keyCache[identifier]?.let { return it }

        // Slow path: load from Keystore (synchronized to prevent duplicate generation)
        synchronized(lockFor(identifier)) {
            // Double-check after acquiring lock
            keyCache[identifier]?.let { return it }

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

            val key = if (keyStore.containsAlias(identifier)) {
                keyStore.getKey(identifier, null) as SecretKey
            } else {
                generateNewKey(identifier, hardwareIsolated, requireUnlockedDevice)
            }

            // Cache the key for future use
            keyCache[identifier] = key
            return key
        }
    }
}
