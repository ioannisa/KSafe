package eu.anifantakis.lib.kvault

import android.content.Context
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
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.AES
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
private fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
private fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

actual class KVault(private val context: Context) {

    @PublishedApi
    internal val json = Json { ignoreUnknownKeys = true }

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

    // ----- Encrypted Storage Helpers -----
    // We store the symmetric key and encrypted ciphertext as Base64 strings.
    private fun symmetricPrefKey(id: String) = stringPreferencesKey("symmetric_$id")
    private fun encryptedPrefKey(key: String) = stringPreferencesKey("encrypted_$key")

    // Retrieve an existing symmetric key or generate a new one.
    // In production you’d use the Android Keystore, but here we persist it in DataStore.
    suspend fun getOrCreateSymmetricKey(id: String, aesGcm: AES.GCM): AES.GCM.Key {
        val storedKeyBase64: String? = dataStore.data.map { it[symmetricPrefKey(id)] }.first()
        return if (storedKeyBase64 != null) {
            val encoded = decodeBase64(storedKeyBase64)
            aesGcm.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, encoded)
        } else {
            val newKey = aesGcm.keyGenerator(AES.Key.Size.B256).generateKey()
            val newKeyEncoded = newKey.encodeToByteArray(AES.Key.Format.RAW)
            val encodedKeyBase64 = encodeBase64(newKeyEncoded)
            dataStore.updateData { preferences ->
                preferences.toMutablePreferences().apply {
                    this[symmetricPrefKey(id)] = encodedKeyBase64
                }
            }
            newKey
        }
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

    suspend inline fun <reified T> putEncrypted(key: String, value: T) {
        // Serialize the value to JSON and get plaintext bytes.
        //val jsonString = json.encodeToString(value)
        val jsonString = json.encodeToString(serializer<T>(), value)
        val plaintext = jsonString.encodeToByteArray()

        val provider = CryptographyProvider.Default
        val aesGcm = provider.get(AES.GCM)
        val symmetricKey = getOrCreateSymmetricKey(key, aesGcm)
        val cipher = symmetricKey.cipher()
        // Encrypting returns a byte array that includes the nonce.
        val ciphertext = cipher.encrypt(plaintext = plaintext)

        storeEncryptedData(key, ciphertext)
    }

    suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        val ciphertext = loadEncryptedData(key) ?: return defaultValue
        val provider = CryptographyProvider.Default
        val aesGcm = provider.get(AES.GCM)
        val symmetricKey = getOrCreateSymmetricKey(key, aesGcm)
        val cipher = symmetricKey.cipher()
        val decryptedBytes = cipher.decrypt(ciphertext = ciphertext)
        val jsonString = decryptedBytes.decodeToString()
        return json.decodeFromString(serializer<T>(), jsonString)
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
}