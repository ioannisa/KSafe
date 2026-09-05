package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage
import eu.anifantakis.lib.ksafe.internal.KSafeInitLock

/**
 * Test-only [KSafeEncryption] with REAL key-lifecycle semantics: key material is minted per
 * alias on first encrypt, [deleteKey] destroys it, and decrypt throws for a missing or
 * replaced key. [FakeEncryption] derives keys from the alias string and keeps decrypting
 * after deletion, so it cannot observe key-loss bugs — a destroyed alias still "decrypts".
 * Use this fake whenever a test must prove that key destruction makes ciphertext unreadable.
 */
internal open class StatefulFakeEncryption : KSafeEncryption {

    // The commit path encrypts a batch's entries CONCURRENTLY, so the mint must be
    // atomic: an unsynchronized getOrPut can hand two callers different key ids for
    // the same alias, leaving one ciphertext permanently undecryptable.
    private val lock = KSafeInitLock()

    private var nextKeyId = 1

    /** Live key material per alias; removed by [deleteKey]. */
    val keysByAlias = mutableMapOf<String, Int>()

    /** Every alias whose key was ever deleted. */
    val deletedKeys = mutableSetOf<String>()

    /** Every alias ever used to encrypt. */
    val encryptedKeys = mutableSetOf<String>()

    override fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        val keyId = lock.withLock {
            encryptedKeys.add(identifier)
            keysByAlias.getOrPut(identifier) { nextKeyId++ }
        }
        val aadHash = aadHash(aad)
        return intBytes(keyId) + intBytes(aadHash) + xor(data, keyId)
    }

    override fun decrypt(
        identifier: String,
        data: ByteArray,
        requireUnlockedDevice: Boolean?,
        aad: ByteArray?,
    ): ByteArray {
        // Same phrasing as the real engines' definitive missing-key failure, so the orphan
        // classifier and rotation treat it as permanent, not transient.
        val keyId = lock.withLock { keysByAlias[identifier] }
            ?: throw IllegalStateException(KSafeEngineMessage.noKeyFound(identifier))
        check(data.size >= 8) { "corrupt ciphertext for '$identifier'" }
        val mintedWith = intFrom(data, 0)
        check(mintedWith == keyId) {
            "authentication failed for '$identifier': ciphertext was encrypted under a replaced key"
        }
        check(intFrom(data, 4) == aadHash(aad)) {
            "authentication failed for '$identifier': AAD mismatch"
        }
        return xor(data.copyOfRange(8, data.size), keyId)
    }

    override fun deleteKey(identifier: String) {
        lock.withLock {
            deletedKeys.add(identifier)
            keysByAlias.remove(identifier)
        }
    }

    /** Live aliases still holding key material (a delete-vs-write race probe for tests). */
    fun liveAliases(): Set<String> = lock.withLock { keysByAlias.keys.toSet() }

    private fun aadHash(aad: ByteArray?): Int = aad?.decodeToString()?.hashCode() ?: 0

    private fun intBytes(v: Int): ByteArray =
        byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())

    private fun intFrom(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 24) or
            ((data[offset + 1].toInt() and 0xFF) shl 16) or
            ((data[offset + 2].toInt() and 0xFF) shl 8) or
            (data[offset + 3].toInt() and 0xFF)

    private fun xor(data: ByteArray, keyId: Int): ByteArray {
        val key = intBytes(keyId * -1640531527) // spread the id so bodies differ per key
        return ByteArray(data.size) { i -> (data[i].toInt() xor key[i % key.size].toInt()).toByte() }
    }
}
