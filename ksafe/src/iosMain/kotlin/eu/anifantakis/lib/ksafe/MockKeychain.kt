package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSProcessInfo

@OptIn(ExperimentalForeignApi::class)
internal object MockKeychain {
    private val storage = mutableMapOf<String, ByteArray>()
    
    fun isSimulator(): Boolean {
        val environment = NSProcessInfo.processInfo.environment
        val simulatorDeviceUdid = environment["SIMULATOR_UDID"] as? String
        return simulatorDeviceUdid != null
    }
    
    fun store(account: String, data: ByteArray): Boolean {
        storage[account] = data.copyOf()
        return true
    }
    
    fun retrieve(account: String): ByteArray? {
        return storage[account]?.copyOf()
    }
    
    fun delete(account: String): Boolean {
        return storage.remove(account) != null
    }
    
    fun getAllKeys(): Set<String> {
        return storage.keys.toSet()
    }
    
    fun clear() {
        storage.clear()
    }
}