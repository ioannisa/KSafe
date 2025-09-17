package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSUserDefaults
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

private const val MOCK_STORAGE_KEY = "eu.anifantakis.ksafe.mockkeychain.storage"

@OptIn(ExperimentalForeignApi::class)
internal object MockKeychain {
    private val userDefaults by lazy { NSUserDefaults.standardUserDefaults }

    private var storage: MutableMap<String, ByteArray> = loadPersistedEntries()
    
    fun isSimulator(): Boolean {
        val environment = NSProcessInfo.processInfo.environment
        val simulatorDeviceUdid = environment["SIMULATOR_UDID"] as? String
        return simulatorDeviceUdid != null
    }
    
    fun store(account: String, data: ByteArray): Boolean {
        storage[account] = data.copyOf()
        persistEntries()
        return true
    }
    
    fun retrieve(account: String): ByteArray? {
        return storage[account]?.copyOf()
    }
    
    fun delete(account: String): Boolean {
        val removed = storage.remove(account) != null
        if (removed) {
            persistEntries()
        }
        return removed
    }
    
    fun getAllKeys(): Set<String> {
        return storage.keys.toSet()
    }
    
    fun clear() {
        storage.clear()
        userDefaults.removeObjectForKey(MOCK_STORAGE_KEY)
        userDefaults.synchronize()
    }

    private fun loadPersistedEntries(): MutableMap<String, ByteArray> {
        val persisted = userDefaults.dictionaryForKey(MOCK_STORAGE_KEY) as? Map<*, *>
        if (persisted == null) return mutableMapOf()

        val restored = mutableMapOf<String, ByteArray>()
        persisted.forEach { (key, value) ->
            val account = key as? String ?: return@forEach
            val encoded = value as? String ?: return@forEach
            val decoded = decodeBase64OrNull(encoded) ?: return@forEach
            restored[account] = decoded
        }
        return restored
    }

    private fun persistEntries() {
        val encoded = storage.mapValues { (_, value) -> encodeBase64(value) }
        userDefaults.setObject(encoded, forKey = MOCK_STORAGE_KEY)
        userDefaults.synchronize()
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun encodeBase64(bytes: ByteArray): String = Base64.encode(bytes)

    @OptIn(ExperimentalEncodingApi::class)
    private fun decodeBase64OrNull(encoded: String): ByteArray? = try {
        Base64.decode(encoded)
    } catch (_: IllegalArgumentException) {
        null
    }
}