package eu.anifantakis.lib.ksafe

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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import java.io.File
import java.nio.file.Paths
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@OptIn(ExperimentalEncodingApi::class)
fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

@OptIn(ExperimentalEncodingApi::class)
@PublishedApi
internal fun decodeBase64(encoded: String): ByteArray = Base64.decode(encoded)

/**
 * JVM implementation of KSafe. This implementation uses the Java
 * cryptography APIs (JCA/JCE) for AES‑256‑GCM encryption and stores both the
 * encrypted values and their associated secret keys in a DataStore
 * preferences file located in the user’s home directory. While not
 * hardware‑backed like Android and iOS, it still provides encryption at rest
 * with a per‑preference random key.
 *
 * @param fileName Optional namespace for the DataStore file. Only lower‑case
 * letters are allowed. If provided, keys and secrets are namespaced by
 * this value.
 */
actual class KSafe(val fileName: String? /* = null */) {

    companion object {
        // Only allow lower‑case letters to avoid path traversal or invalid names.
        private val fileNameRegex = Regex("[a-z]+")
        const val GCM_TAG_LENGTH = 128
    }

    init {
        if (fileName != null && !fileName.matches(fileNameRegex)) {
            throw IllegalArgumentException("File name must contain only lowercase letters")
        }
    }

    // JSON serializer with unknown keys ignored to handle forwards‑compatible schema changes.
    @PublishedApi
    internal val json = Json { ignoreUnknownKeys = true }

    // DataStore instance. We place the file under a hidden directory in the
    // user's home folder. Each KSafe instance gets its own file, so that
    // different file names result in isolated vaults.
    @PublishedApi
    internal val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
        produceFile = {
            val homeDir = Paths.get(System.getProperty("user.home")).toFile()
            val baseDir = File(homeDir, ".eu_anifantakis_ksafe")
            baseDir.mkdirs()

            val base = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" }
                ?: "eu_anifantakis_ksafe_datastore"
            val fnameWithSuffix = "$base.preferences_pb"
            File(baseDir, fnameWithSuffix)
        }
    )

    /**
     * Retrieve (or generate) the AES key associated with a particular alias.
     * Each preference key uses its own AES‑256 key. Keys are stored in the
     * DataStore as Base64‑encoded strings under the `ksafe_key_<alias>` entry.
     */
    @PublishedApi
    internal suspend fun getOrCreateSecretKey(alias: String): SecretKey {
        val keyPref = stringPreferencesKey("ksafe_key_$alias")
        val preferences = dataStore.data.first()
        val existing = preferences[keyPref]
        if (existing != null) {
            val keyBytes = decodeBase64(existing)
            return SecretKeySpec(keyBytes, "AES")
        }
        // Generate a new 256‑bit AES key
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        val secretKey = keyGen.generateKey()
        val encoded = encodeBase64(secretKey.encoded)
        dataStore.edit { prefs ->
            prefs[keyPref] = encoded
        }
        return secretKey
    }

    // Construct the DataStore preference key for an encrypted value
    @PublishedApi
    internal fun encryptedPrefKey(key: String) = stringPreferencesKey("encrypted_$key")

    // ----- Unencrypted Storage Helpers -----
    @PublishedApi
    @Suppress("UNCHECKED_CAST")
    internal suspend inline fun <reified T> getUnencrypted(key: String, defaultValue: T): T {
        // Determine preference key type based on the default value
        val prefKey: Preferences.Key<Any> = when (defaultValue) {
            is Boolean -> booleanPreferencesKey(key)
            is Int -> intPreferencesKey(key)
            is Float -> floatPreferencesKey(key)
            is Long -> longPreferencesKey(key)
            is String -> stringPreferencesKey(key)
            is Double -> doublePreferencesKey(key)
            else -> stringPreferencesKey(key)
        } as Preferences.Key<Any>
        return dataStore.data.map { prefs ->
            val stored = prefs[prefKey]
            when (defaultValue) {
                is Boolean -> (stored as? Boolean ?: defaultValue) as T
                is Int -> {
                    when (stored) {
                        is Int -> stored as T
                        is Long -> if (stored in Int.MIN_VALUE..Int.MAX_VALUE) stored.toInt() as T else defaultValue
                        else -> defaultValue
                    }
                }
                is Long -> {
                    when (stored) {
                        is Long -> stored as T
                        is Int -> stored.toLong() as T
                        else -> defaultValue
                    }
                }
                is Float -> (stored as? Float ?: defaultValue) as T
                is String -> (stored as? String ?: defaultValue) as T
                is Double -> (stored as? Double ?: defaultValue) as T
                else -> {
                    val jsonString = stored as? String ?: return@map defaultValue
                    try {
                        json.decodeFromString(serializer<T>(), jsonString)
                    } catch (_: Exception) {
                        defaultValue
                    }
                }
            }
        }.first()
    }

    @PublishedApi
    @Suppress("UNCHECKED_CAST")
    internal suspend inline fun <reified T> putUnencrypted(key: String, value: T) {
        val prefKey: Preferences.Key<Any> = when (value) {
            is Boolean -> booleanPreferencesKey(key)
            is Number -> {
                when {
                    value is Int || (value is Long && value in Int.MIN_VALUE..Int.MAX_VALUE) -> intPreferencesKey(key)
                    value is Long -> longPreferencesKey(key)
                    value is Float -> floatPreferencesKey(key)
                    value is Double -> doublePreferencesKey(key)
                    else -> stringPreferencesKey(key)
                }
            }
            is String -> stringPreferencesKey(key)
            else -> stringPreferencesKey(key)
        } as Preferences.Key<Any>
        val stored: Any = when (value) {
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
        dataStore.edit { prefs ->
            prefs[prefKey] = stored
        }
    }

    // ----- Encrypted Storage Helpers -----
    @PublishedApi
    internal suspend inline fun <reified T> getEncrypted(key: String, defaultValue: T): T {
        val encKey = encryptedPrefKey(key)
        val preferences = dataStore.data.first()
        val encryptedString = preferences[encKey] ?: return defaultValue

        // Build an alias combining file name and key to avoid collisions
        val alias = fileName?.let { "$it:$key" } ?: key
        val secretKey = getOrCreateSecretKey(alias)
        val encryptedBytes = decodeBase64(encryptedString)

        // Minimum length includes 12 byte IV and 16 byte tag
        if (encryptedBytes.size < 13) return defaultValue
        val iv = encryptedBytes.copyOfRange(0, 12)
        val cipherBytes = encryptedBytes.copyOfRange(12, encryptedBytes.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        val plainBytes = try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.doFinal(cipherBytes)
        } catch (_: Exception) {
            return defaultValue
        }

        val rawString = plainBytes.toString(Charsets.UTF_8)

        // Unified deserialization for consistency with Android/iOS
        return try {
            json.decodeFromString(serializer<T>(), rawString)
        } catch (_: Exception) {
            defaultValue
        }
    }

    @PublishedApi
    internal suspend inline fun <reified T> putEncrypted(key: String, value: T) {
        val alias = fileName?.let { "$it:$key" } ?: key
        val secretKey = getOrCreateSecretKey(alias)

        // Unified serialization: Convert everything to JSON first for consistency with Android/iOS
        val rawString = json.encodeToString(serializer<T>(), value)

        val plainBytes = rawString.toByteArray(Charsets.UTF_8)
        val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        val cipherBytes = cipher.doFinal(plainBytes)
        val encryptedBytes = iv + cipherBytes
        val encryptedString = encodeBase64(encryptedBytes)

        dataStore.edit { prefs ->
            prefs[encryptedPrefKey(key)] = encryptedString
        }
    }

    // ----- Public API implementation -----
    actual inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean): T {
        return runBlocking { get(key, defaultValue, encrypted) }
    }

    actual inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean) {
        runBlocking { put(key, value, encrypted) }
    }

    actual suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean): T {
        return if (!encrypted) getUnencrypted(key, defaultValue) else getEncrypted(key, defaultValue)
    }

    actual inline fun <reified T> getFlow(key: String, defaultValue: T, encrypted: Boolean): Flow<T> {
        return if (!encrypted) {
            // Map unencrypted preferences to the expected type
            dataStore.data.map { prefs ->
                @Suppress("UNCHECKED_CAST")
                val prefKey: Preferences.Key<Any> = when (defaultValue) {
                    is Boolean -> booleanPreferencesKey(key)
                    is Int -> intPreferencesKey(key)
                    is Float -> floatPreferencesKey(key)
                    is Long -> longPreferencesKey(key)
                    is String -> stringPreferencesKey(key)
                    is Double -> doublePreferencesKey(key)
                    else -> stringPreferencesKey(key)
                } as Preferences.Key<Any>
                val stored = prefs[prefKey]
                when (defaultValue) {
                    is Boolean -> (stored as? Boolean ?: defaultValue) as T
                    is Int -> {
                        when (stored) {
                            is Int -> stored as T
                            is Long -> if (stored in Int.MIN_VALUE..Int.MAX_VALUE) stored.toInt() as T else defaultValue
                            else -> defaultValue
                        }
                    }
                    is Long -> {
                        when (stored) {
                            is Long -> stored as T
                            is Int -> stored.toLong() as T
                            else -> defaultValue
                        }
                    }
                    is Float -> (stored as? Float ?: defaultValue) as T
                    is String -> (stored as? String ?: defaultValue) as T
                    is Double -> (stored as? Double ?: defaultValue) as T
                    else -> {
                        val jsonString = stored as? String ?: return@map defaultValue
                        try {
                            json.decodeFromString(serializer<T>(), jsonString)
                        } catch (_: Exception) {
                            defaultValue
                        }
                    }
                }
            }.distinctUntilChanged()
        } else {
            // Map encrypted preferences to the expected type
            dataStore.data.map { prefs ->
                val encryptedString = prefs[encryptedPrefKey(key)] ?: return@map defaultValue
                val alias = fileName?.let { "$it:$key" } ?: key

                // Call suspend function directly since we are in a suspend map block
                // Do not use runBlocking here to avoid blocking the IO thread
                val secretKey = getOrCreateSecretKey(alias)

                val encryptedBytes = decodeBase64(encryptedString)
                if (encryptedBytes.size < 13) return@map defaultValue
                val iv = encryptedBytes.copyOfRange(0, 12)
                val cipherBytes = encryptedBytes.copyOfRange(12, encryptedBytes.size)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

                val plainBytes = try {
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
                    cipher.doFinal(cipherBytes)
                } catch (_: Exception) {
                    return@map defaultValue
                }

                val rawString = plainBytes.toString(Charsets.UTF_8)

                // Unified deserialization
                try {
                    json.decodeFromString(serializer<T>(), rawString)
                } catch (_: Exception) {
                    defaultValue
                }
            }.distinctUntilChanged()
        }
    }

    actual suspend inline fun <reified T> put(key: String, value: T, encrypted: Boolean) {
        if (!encrypted) putUnencrypted(key, value) else putEncrypted(key, value)
    }

    actual suspend fun delete(key: String) {
        dataStore.edit { prefs ->
            // 1. Remove unencrypted values of all possible types to ensure clean state
            prefs.remove(booleanPreferencesKey(key))
            prefs.remove(intPreferencesKey(key))
            prefs.remove(longPreferencesKey(key))
            prefs.remove(floatPreferencesKey(key))
            prefs.remove(doublePreferencesKey(key))
            prefs.remove(stringPreferencesKey(key))

            // 2. Remove the encrypted payload itself (orphaned data fix)
            prefs.remove(encryptedPrefKey(key))

            // 3. Remove the unique AES key generated for this specific preference
            val alias = fileName?.let { "$it:$key" } ?: key
            val keyPref = stringPreferencesKey("ksafe_key_$alias")
            prefs.remove(keyPref)
        }
    }

    actual fun deleteDirect(key: String) {
        runBlocking { delete(key) }
    }

    actual suspend fun clearAll() {
        dataStore.edit { it.clear() }

        // Since we are strictly file-based on JVM, deleting the file ensures
        // no artifacts remain.
        try {
            val homeDir = Paths.get(System.getProperty("user.home")).toFile()
            val baseDir = File(homeDir, ".eu_anifantakis_ksafe")

            val base = fileName?.let { "eu_anifantakis_ksafe_datastore_$it" }
                ?: "eu_anifantakis_ksafe_datastore"
            val fnameWithSuffix = "$base.preferences_pb"
            val file = File(baseDir, fnameWithSuffix)

            if (file.exists()) {
                file.delete()
            }
        } catch (e: Exception) {
            // Ignore file deletion errors, the dataStore.clear() above is sufficient for logic
        }
    }
}