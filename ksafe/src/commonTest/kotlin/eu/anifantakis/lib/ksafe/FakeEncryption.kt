package eu.anifantakis.lib.ksafe

/**
 * Fake implementation of [KSafeEncryption] for testing purposes.
 *
 * This implementation performs a simple XOR "encryption" that is NOT secure but allows
 * testing the KSafe logic without requiring platform-specific keystores or emulators.
 *
 * Features:
 * - Deterministic: Same input + identifier produces same output
 * - Reversible: XOR with same key reverses the operation
 * - Tracks calls for verification in tests
 *
 * ## Usage in Tests
 * ```kotlin
 * val fakeEngine = FakeEncryption()
 * val ksafe = KSafe(
 *     context = testContext,
 *     encryptionEngine = fakeEngine
 * )
 *
 * ksafe.putDirect("key", "value")
 * assertEquals("value", ksafe.getDirect("key", ""))
 *
 * // Verify encryption was called
 * assertTrue(fakeEngine.encryptedKeys.contains("expectedKeyAlias"))
 * ```
 */
@PublishedApi
internal class FakeEncryption : KSafeEncryption {

    /**
     * Set of key identifiers that have been encrypted.
     * Useful for verifying in tests that encryption was called.
     */
    val encryptedKeys = mutableSetOf<String>()

    /**
     * Set of key identifiers that have been decrypted.
     * Useful for verifying in tests that decryption was called.
     */
    val decryptedKeys = mutableSetOf<String>()

    /**
     * Set of key identifiers that have been deleted.
     * Useful for verifying in tests that key deletion was called.
     */
    val deletedKeys = mutableSetOf<String>()

    /**
     * "Encrypts" data using a simple XOR operation.
     *
     * The XOR key is derived from the identifier, making the encryption deterministic
     * and allowing the same data to be "decrypted" by applying the same operation.
     */
    override fun encrypt(identifier: String, data: ByteArray): ByteArray {
        encryptedKeys.add(identifier)
        val key = deriveKey(identifier)
        return xorWithKey(data, key)
    }

    /**
     * "Decrypts" data using the same XOR operation.
     *
     * Since XOR is its own inverse, this produces the original plaintext.
     */
    override fun decrypt(identifier: String, data: ByteArray): ByteArray {
        decryptedKeys.add(identifier)
        val key = deriveKey(identifier)
        return xorWithKey(data, key)
    }

    /**
     * Records that a key was "deleted".
     *
     * Since there's no actual key storage, this just tracks the call.
     */
    override fun deleteKey(identifier: String) {
        deletedKeys.add(identifier)
    }

    /**
     * Resets all tracking sets. Call this between tests to ensure isolation.
     */
    fun reset() {
        encryptedKeys.clear()
        decryptedKeys.clear()
        deletedKeys.clear()
    }

    /**
     * Derives a simple XOR key from the identifier.
     * Uses the identifier's hash code to generate a repeatable key.
     */
    private fun deriveKey(identifier: String): ByteArray {
        val hash = identifier.hashCode()
        return byteArrayOf(
            (hash shr 24).toByte(),
            (hash shr 16).toByte(),
            (hash shr 8).toByte(),
            hash.toByte()
        )
    }

    /**
     * Performs XOR operation on data with a repeating key.
     */
    private fun xorWithKey(data: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(data.size) { i ->
            (data[i].toInt() xor key[i % key.size].toInt()).toByte()
        }
    }
}
