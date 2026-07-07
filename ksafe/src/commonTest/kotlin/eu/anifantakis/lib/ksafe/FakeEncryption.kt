package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption

/**
 * Test-only [KSafeEncryption] that "encrypts" via a deterministic, reversible XOR so KSafe
 * logic can be exercised without platform keystores or emulators. Tracks encrypt/decrypt/delete
 * calls so tests can assert which identifiers were touched.
 */
@PublishedApi
internal class FakeEncryption : KSafeEncryption {

    /** Key identifiers that have been encrypted. */
    val encryptedKeys = mutableSetOf<String>()

    /** Key identifiers that have been decrypted. */
    val decryptedKeys = mutableSetOf<String>()

    /** Key identifiers that have been deleted. */
    val deletedKeys = mutableSetOf<String>()

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?
    ): ByteArray {
        encryptedKeys.add(identifier)
        val key = deriveKey(identifier)
        return xorWithKey(data, key)
    }

    override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
        decryptedKeys.add(identifier)
        val key = deriveKey(identifier)
        return xorWithKey(data, key)
    }

    override fun deleteKey(identifier: String) {
        deletedKeys.add(identifier)
    }

    /** Clears all tracking sets; call between tests for isolation. */
    fun reset() {
        encryptedKeys.clear()
        decryptedKeys.clear()
        deletedKeys.clear()
    }

    private fun deriveKey(identifier: String): ByteArray {
        val hash = identifier.hashCode()
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
