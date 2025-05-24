package eu.anifantakis.lib.kvault

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.doublePreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStoreFile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
private fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
private fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

actual class KVault(private val context: Context) {

    @PublishedApi
    internal val json = Json { ignoreUnknownKeys = true }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS_PREFIX = "eu.anifantakis.kvault."
        private const val GCM_TAG_LENGTH = 128
    }

    // Create a DataStore for our preferences.
    @PublishedApi
    internal val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
        produceFile = { context.preferencesDataStoreFile("eu_anifantakis_kvault_datastore") }
    )

    // ----- Unencrypted Storage Helpers -----

    @PublishedApi
    internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        val preferencesKey: Preferences.Key<Any> = when (defaultValue) {
            is Boolean -> booleanPreferencesKey(key)
            is Int -> intPreferencesKey(key)
            is Float -> floatPreferencesKey(key)
            is Long -> longPreferencesKey(key)
            is String -> stringPreferencesKey(key)
            is Double -> doublePreferencesKey(key)
            else -> stringPreferencesKey(key)
        } as Preferences.Key<Any>

        return dataStore.data.map { preferences ->
            val storedValue = preferences[preferencesKey]
            when (defaultValue) {
                is Boolean -> (storedValue as? Boolean ?: defaultValue) as T
                is Int -> {
                    when (storedValue) {
                        is Int -> storedValue as T
                        is Long -> if (storedValue in Int.MIN_VALUE..Int.MAX_VALUE) storedValue.toInt() as T else defaultValue
                        else -> defaultValue
                    }
                }
                is Long -> {
                    when (storedValue) {
                        is Long -> storedValue as T
                        is Int -> storedValue.toLong() as T
                        else -> defaultValue
                    }
                }
                is Float -> (storedValue as? Float ?: defaultValue) as T
                is String -> (storedValue as? String ?: defaultValue) as T
                is Double -> (storedValue as? Double ?: defaultValue) as T
                else -> {
                    val jsonString = storedValue as? String ?: return@map defaultValue
                    try {
                        json.decodeFromString(serializer<T>(), jsonString)
                    } catch (e: Exception) {
                        defaultValue
                    }
                }
            }
        }.first()
    }

    @PublishedApi
    internal suspend inline fun <reified T> putUnencrypted(key: String, value: T) {
        val preferencesKey: Preferences.Key<Any> = when (value) {
            is Boolean -> booleanPreferencesKey(key)
            is Number -> {
                when {
                    value is Int || (value is Long && value in Int.MIN_VALUE..Int.MAX_VALUE) ->
                        intPreferencesKey(key)
                    value is Long -> longPreferencesKey(key)
                    value is Float -> floatPreferencesKey(key)
                    value is Double -> doublePreferencesKey(key)
                    else -> stringPreferencesKey(key)
                }
            }
            is String -> stringPreferencesKey(key)
            else -> stringPreferencesKey(key)
        } as Preferences.Key<Any>

        val storedValue: Any = when (value) {
            is Boolean -> value
            is Number -> {
                when {
                    value is Int || (value is Long && value in Int.MIN_VALUE..Int.MAX_VALUE) -> value.toInt()
                    else -> value
                }
            }
            is String -> value
            else -> json.encodeToString(serializer<T>(), value)
        }

        dataStore.updateData { preferences ->
            preferences.toMutablePreferences().apply {
                this[preferencesKey] = storedValue
            }
        }
    }

    // ----- Android Keystore Encryption Helpers -----

    private fun encryptedPrefKey(key: String) = stringPreferencesKey("encrypted_$key")

    /**
     * Gets or creates a secret key in Android Keystore
     */
    @RequiresApi(Build.VERSION_CODES.M)
    private fun getOrCreateSecretKey(keyAlias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }

        // Check if key already exists
        if (keyStore.containsAlias(keyAlias)) {
            return keyStore.getKey(keyAlias, null) as SecretKey
        }

        // Generate new key
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    /**
     * Encrypts data using Android Keystore
     */
    @RequiresApi(Build.VERSION_CODES.M)
    fun encryptWithKeystore(keyAlias: String, plaintext: ByteArray): ByteArray {
        val secretKey = getOrCreateSecretKey(keyAlias)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)

        // Combine IV and ciphertext
        return iv + ciphertext
    }

    /**
     * Decrypts data using Android Keystore
     */
    @RequiresApi(Build.VERSION_CODES.M)
    fun decryptWithKeystore(keyAlias: String, encryptedData: ByteArray): ByteArray {
        val secretKey = getOrCreateSecretKey(keyAlias)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        // Extract IV and ciphertext
        val iv = encryptedData.sliceArray(0..11)
        val ciphertext = encryptedData.sliceArray(12 until encryptedData.size)

        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return cipher.doFinal(ciphertext)
    }

    suspend fun storeEncryptedData(key: String, data: ByteArray) {
        val encoded = encodeBase64(data)
        dataStore.updateData { preferences ->
            preferences.toMutablePreferences().apply {
                this[encryptedPrefKey(key)] = encoded
            }
        }
    }

    suspend fun loadEncryptedData(key: String): ByteArray? {
        val stored = dataStore.data.map { it[encryptedPrefKey(key)] }.first()
        return stored?.let { decodeBase64(it) }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    suspend inline fun <reified T> putEncrypted(key: String, value: T) {
        // Serialize the value to JSON and get plaintext bytes.
        val jsonString = json.encodeToString(serializer<T>(), value)
        val plaintext = jsonString.encodeToByteArray()

        // Use Android Keystore for encryption
        val keyAlias = KEY_ALIAS_PREFIX + key
        val ciphertext = encryptWithKeystore(keyAlias, plaintext)

        storeEncryptedData(key, ciphertext)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        val ciphertext = loadEncryptedData(key) ?: return defaultValue

        return try {
            // Use Android Keystore for decryption
            val keyAlias = KEY_ALIAS_PREFIX + key
            val decryptedBytes = decryptWithKeystore(keyAlias, ciphertext)
            val jsonString = decryptedBytes.decodeToString()
            json.decodeFromString(serializer<T>(), jsonString)
        } catch (e: Exception) {
            // If decryption fails (e.g., key was deleted), return default value
            defaultValue
        }
    }

    actual suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean): T {
        return if (encrypted) {
            getEncrypted(key, defaultValue)
        } else {
            getUnencrypted(key, defaultValue)
        }
    }

    actual inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean): T {
        return runBlocking {
            get(key, defaultValue, encrypted)
        }
    }

    actual suspend inline fun <reified T> put(key: String, value: T, encrypted: Boolean) {
        if (encrypted) {
            putEncrypted(key, value)
        } else {
            putUnencrypted(key, value)
        }
    }

    actual inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean) {
        CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
            put(key, value, encrypted)
        }
    }

    /**
     * Deletes a value from DataStore.
     *
     * @param key The key of the value to delete.
     */
    actual suspend fun delete(key: String) {
        val dataKey = stringPreferencesKey(key)
        dataStore.edit { preferences ->
            preferences.remove(dataKey)
        }

        // Also try to delete the corresponding encryption key from Keystore
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                load(null)
            }
            val keyAlias = KEY_ALIAS_PREFIX + key
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }
        } catch (e: Exception) {
            // Ignore errors when deleting from keystore
        }
    }

    /**
     * Deletes a value from DataStore without using coroutines.
     * This function is **non-blocking**.
     *
     * @param key The key of the value to delete.
     */
    actual fun deleteDirect(key: String) {
        CoroutineScope(Dispatchers.IO + SupervisorJob()).launch {
            delete(key)
        }
    }

    /**
     * Clear all data including Keystore entries.
     * Useful for complete cleanup or testing.
     * Note: On Android, Keystore entries are automatically deleted on app uninstall.
     */
    suspend fun clearAll() {
        // Get all encrypted keys before clearing
        val encryptedKeys = mutableSetOf<String>()
        val preferences = dataStore.data.first()

        preferences.asMap().forEach { (key, _) ->
            if (key.name.startsWith("encrypted_")) {
                val keyId = key.name.removePrefix("encrypted_")
                encryptedKeys.add(keyId)
            }
        }

        // Clear all DataStore preferences
        dataStore.edit { it.clear() }

        // Delete all associated Keystore entries
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }

        encryptedKeys.forEach { keyId ->
            val keyAlias = KEY_ALIAS_PREFIX + keyId
            try {
                if (keyStore.containsAlias(keyAlias)) {
                    keyStore.deleteEntry(keyAlias)
                }
            } catch (e: Exception) {
                // Ignore errors when deleting from keystore
            }
        }
    }
}