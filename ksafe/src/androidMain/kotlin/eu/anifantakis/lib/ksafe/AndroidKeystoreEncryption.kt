package eu.anifantakis.lib.ksafe

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
 * @property config Configuration for key generation (key size, user authentication requirements)
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

    override fun encrypt(identifier: String, data: ByteArray): ByteArray {
        val secretKey = getOrCreateSecretKey(identifier)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val ciphertext = cipher.doFinal(data)

        // Return IV prepended to ciphertext
        return iv + ciphertext
    }

    override fun decrypt(identifier: String, data: ByteArray): ByteArray {
        val secretKey = getOrCreateSecretKey(identifier)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        // Extract IV (first 12 bytes) and ciphertext
        val iv = data.sliceArray(0 until GCM_IV_LENGTH)
        val ciphertext = data.sliceArray(GCM_IV_LENGTH until data.size)

        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return cipher.doFinal(ciphertext)
    }

    override fun deleteKey(identifier: String) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(identifier)) {
                keyStore.deleteEntry(identifier)
            }
        } catch (_: Exception) {
            // Silently ignore - key may not exist or keystore may be unavailable
        }
    }

    /**
     * Gets an existing key from the Keystore or creates a new one if it doesn't exist.
     *
     * Key generation parameters:
     * - Algorithm: AES
     * - Block Mode: GCM (hardcoded for security)
     * - Padding: None (hardcoded for security)
     * - Key Size: Configurable via [KSafeConfig.keySize]
     * - User Authentication: Configurable via [KSafeConfig.userAuthenticationRequired]
     */
    private fun getOrCreateSecretKey(keyAlias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        // Return existing key if available
        if (keyStore.containsAlias(keyAlias)) {
            return keyStore.getKey(keyAlias, null) as SecretKey
        }

        // Generate new key with configured parameters
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(config.keySize)

        // Apply user authentication requirements if configured
        if (config.userAuthenticationRequired) {
            builder.setUserAuthenticationRequired(true)
            if (config.userAuthenticationValiditySeconds > 0) {
                @Suppress("DEPRECATION")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationParameters(
                        config.userAuthenticationValiditySeconds,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    )
                } else {
                    builder.setUserAuthenticationValidityDurationSeconds(
                        config.userAuthenticationValiditySeconds
                    )
                }
            }
        }

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }
}
