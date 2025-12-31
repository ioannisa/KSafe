package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * JVM implementation of [KSafeEncryption] using software-backed encryption.
 *
 * Unlike Android/iOS, JVM lacks a standard hardware keystore. This implementation:
 * - Uses AES-256-GCM encryption via `javax.crypto`
 * - Stores keys in DataStore alongside encrypted data
 * - Relies on OS file permissions (0700 on POSIX systems) for key protection
 *
 * **Security Note:** This provides encryption at rest but keys are stored in software.
 * For higher security on JVM, consider using a Hardware Security Module (HSM) or
 * a cloud-based key management service.
 *
 * @property config Configuration for key generation (key size)
 * @property dataStore DataStore instance for key persistence
 */
@PublishedApi
internal class JvmSoftwareEncryption(
    private val config: KSafeConfig = KSafeConfig(),
    private val dataStore: DataStore<Preferences>
) : KSafeEncryption {

    companion object {
        private const val GCM_TAG_LENGTH = 128
        private const val GCM_IV_LENGTH = 12
        private const val KEY_PREFIX = "ksafe_key_"
    }

    override fun encrypt(identifier: String, data: ByteArray): ByteArray {
        val secretKey = runBlocking { getOrCreateSecretKey(identifier) }

        // Generate random IV
        val iv = ByteArray(GCM_IV_LENGTH)
        SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        val ciphertext = cipher.doFinal(data)

        // Return IV prepended to ciphertext
        return iv + ciphertext
    }

    override fun decrypt(identifier: String, data: ByteArray): ByteArray {
        val secretKey = runBlocking { getOrCreateSecretKey(identifier) }

        // Extract IV (first 12 bytes) and ciphertext
        val iv = data.copyOfRange(0, GCM_IV_LENGTH)
        val ciphertext = data.copyOfRange(GCM_IV_LENGTH, data.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return cipher.doFinal(ciphertext)
    }

    override fun deleteKey(identifier: String) {
        runBlocking {
            val keyPref = stringPreferencesKey("$KEY_PREFIX$identifier")
            dataStore.edit { prefs ->
                prefs.remove(keyPref)
            }
        }
    }

    /**
     * Gets an existing key from DataStore or creates a new one if it doesn't exist.
     *
     * Keys are stored as Base64-encoded byte arrays in DataStore preferences.
     *
     * @param alias The key identifier
     * @return The secret key for encryption/decryption
     */
    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun getOrCreateSecretKey(alias: String): SecretKey {
        val keyPref = stringPreferencesKey("$KEY_PREFIX$alias")
        val preferences = dataStore.data.first()
        val existing = preferences[keyPref]

        if (existing != null) {
            val keyBytes = Base64.decode(existing)
            return SecretKeySpec(keyBytes, "AES")
        }

        // Generate new key with configured size
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(config.keySize)
        val secretKey = keyGen.generateKey()

        // Store in DataStore
        val encoded = Base64.encode(secretKey.encoded)
        dataStore.edit { prefs ->
            prefs[keyPref] = encoded
        }

        return secretKey
    }
}
