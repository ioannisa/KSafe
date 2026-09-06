package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeInitLock

/**
 * Test-only [KSafeEncryption] that "encrypts" via a deterministic, reversible XOR so KSafe
 * logic can be exercised without platform keystores or emulators. Tracks encrypt/decrypt/delete
 * calls so tests can assert which identifiers were touched.
 */
@PublishedApi
internal class FakeEncryption : KSafeEncryption {

    // The commit path encrypts a batch concurrently, so unguarded set adds would race:
    // lost tracking entries at best, a corrupted HashSet at worst.
    private val lock = KSafeInitLock()

    val encryptedKeys = mutableSetOf<String>()

    val decryptedKeys = mutableSetOf<String>()

    val deletedKeys = mutableSetOf<String>()

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        lock.withLock { encryptedKeys.add(identifier) }
        val key = deriveKey(identifier, aad)
        return xorWithKey(data, key)
    }

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray {
        lock.withLock { decryptedKeys.add(identifier) }
        val key = deriveKey(identifier, aad)
        return xorWithKey(data, key)
    }

    override fun deleteKey(identifier: String) {
        lock.withLock { deletedKeys.add(identifier) }
    }

    fun reset() {
        lock.withLock {
            encryptedKeys.clear()
            decryptedKeys.clear()
            deletedKeys.clear()
        }
    }

    private fun deriveKey(identifier: String, aad: ByteArray? = null): ByteArray {
        // AAD folds into the key so a mismatched AAD yields garbage — modelling GCM's
        // authentication failure closely enough for swap/tamper tests.
        val hash = identifier.hashCode() * 31 + (aad?.decodeToString()?.hashCode() ?: 0)
        return byteArrayOf(
            (hash shr 24).toByte(),
            (hash shr 16).toByte(),
            (hash shr 8).toByte(),
            hash.toByte()
        )
    }

    private fun xorWithKey(data: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(data.size) { i ->
            (data[i].toInt() xor key[i % key.size].toInt()).toByte()
        }
    }
}
