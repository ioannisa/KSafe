package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleAesGcm
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * NIST AES-GCM vectors pin the KSafe-owned CryptoKit bridge to the same framing and primitive
 * semantics used by the former cryptography-kotlin provider and by the Android/JVM/Web engines.
 */
class AppleAesGcmTest {

    @Test
    fun aes128_emptyPlaintext_matchesNistVector() {
        assertVector(
            keyHex = "00000000000000000000000000000000",
            nonceHex = "000000000000000000000000",
            plaintextHex = "",
            ciphertextAndTagHex = "58e2fccefa7e3061367f1d57a4e7455a",
        )
    }

    @Test
    fun aes128_singleBlock_matchesNistVector() {
        assertVector(
            keyHex = "00000000000000000000000000000000",
            nonceHex = "000000000000000000000000",
            plaintextHex = "00000000000000000000000000000000",
            ciphertextAndTagHex =
                "0388dace60b6a392f328c2b971b2fe78" +
                    "ab6e47d42cec13bdf53a67b21257bddf",
        )
    }

    @Test
    fun aes256_singleBlock_matchesNistVector() {
        assertVector(
            keyHex =
                "00000000000000000000000000000000" +
                    "00000000000000000000000000000000",
            nonceHex = "000000000000000000000000",
            plaintextHex = "00000000000000000000000000000000",
            ciphertextAndTagHex =
                "cea7403d4d606b6e074ec5d3baf39d18" +
                    "d0d1c8a799996bf0265b98b5d48ab919",
        )
    }

    @Test
    fun aes256_withAad_matchesFrozenCrossProviderVector() {
        val key =
            "000102030405060708090a0b0c0d0e0f" +
                "101112131415161718191a1b1c1d1e1f"
        val nonce = "a0a1a2a3a4a5a6a7a8a9aaab"
        val plaintext =
            "4b53616665206c65676163792063727970746f6772617068792d6b6f746c696e2066697874757265"
        val aad = "6b736166652d76332d616164"
        val ciphertextAndTag =
            "ad4b1d4b20eb6eda0504e4aa2719b2a700d83677e0d63204e5234de90bc71c6f" +
                "f2102e87db572158cfd724805576c716c8bc60cb14f6ac7e"

        val encrypted = AppleAesGcm.encrypt(
            key = key.hexToBytes(),
            plaintext = plaintext.hexToBytes(),
            authenticatedData = aad.hexToBytes(),
            nonce = nonce.hexToBytes(),
        )

        assertContentEquals(
            nonce.hexToBytes() + ciphertextAndTag.hexToBytes(),
            encrypted,
        )
        assertContentEquals(
            plaintext.hexToBytes(),
            AppleAesGcm.decrypt(key.hexToBytes(), encrypted, aad.hexToBytes()),
        )
    }

    @Test
    fun aad_roundTrips_forBothSupportedKeySizes() {
        for (keySizeBytes in listOf(16, 32)) {
            val key = ByteArray(keySizeBytes) { (it * 11 + 3).toByte() }
            val nonce = ByteArray(AppleAesGcm.NONCE_SIZE_BYTES) { (it * 7 + 1).toByte() }
            val plaintext = ByteArray(257) { (it * 13 + 5).toByte() }
            val aad = "store|key|DEFAULT|generation=2".encodeToByteArray()

            val encrypted = AppleAesGcm.encrypt(key, plaintext, aad, nonce)

            assertEquals(
                AppleAesGcm.NONCE_SIZE_BYTES + plaintext.size + AppleAesGcm.TAG_SIZE_BYTES,
                encrypted.size,
            )
            assertContentEquals(nonce, encrypted.copyOfRange(0, AppleAesGcm.NONCE_SIZE_BYTES))
            assertContentEquals(plaintext, AppleAesGcm.decrypt(key, encrypted, aad))
        }
    }

    @Test
    fun tamperedCiphertextTagAndAad_areRejected() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(AppleAesGcm.NONCE_SIZE_BYTES) { (it + 20).toByte() }
        val aad = "authenticated metadata".encodeToByteArray()
        val encrypted = AppleAesGcm.encrypt(
            key,
            "sensitive payload".encodeToByteArray(),
            aad,
            nonce,
        )

        val tamperedCiphertext = encrypted.copyOf().also {
            it[AppleAesGcm.NONCE_SIZE_BYTES] =
                (it[AppleAesGcm.NONCE_SIZE_BYTES].toInt() xor 1).toByte()
        }
        val tamperedTag = encrypted.copyOf().also {
            it[it.lastIndex] = (it[it.lastIndex].toInt() xor 1).toByte()
        }

        assertFailsWith<IllegalStateException> {
            AppleAesGcm.decrypt(key, tamperedCiphertext, aad)
        }
        assertFailsWith<IllegalStateException> {
            AppleAesGcm.decrypt(key, tamperedTag, aad)
        }
        assertFailsWith<IllegalStateException> {
            AppleAesGcm.decrypt(key, encrypted, "wrong metadata".encodeToByteArray())
        }
    }

    @Test
    fun invalidKeyNonceAndCiphertextSizes_areRejectedBeforeInterop() {
        assertFailsWith<IllegalArgumentException> {
            AppleAesGcm.encrypt(ByteArray(24), ByteArray(0), authenticatedData = null)
        }
        assertFailsWith<IllegalArgumentException> {
            AppleAesGcm.encrypt(
                ByteArray(16),
                ByteArray(0),
                authenticatedData = null,
                nonce = ByteArray(11),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AppleAesGcm.decrypt(ByteArray(16), ByteArray(27), authenticatedData = null)
        }
    }

    private fun assertVector(
        keyHex: String,
        nonceHex: String,
        plaintextHex: String,
        ciphertextAndTagHex: String,
    ) {
        val key = keyHex.hexToBytes()
        val nonce = nonceHex.hexToBytes()
        val plaintext = plaintextHex.hexToBytes()
        val expected = nonce + ciphertextAndTagHex.hexToBytes()

        val encrypted = AppleAesGcm.encrypt(
            key,
            plaintext,
            authenticatedData = null,
            nonce = nonce,
        )

        assertContentEquals(expected, encrypted)
        assertContentEquals(
            plaintext,
            AppleAesGcm.decrypt(key, encrypted, authenticatedData = null),
        )
    }

    private fun String.hexToBytes(): ByteArray {
        require(length % 2 == 0)
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    @Test
    fun emptyPlaintextAndEmptyAad_crossTheBridgeAsNullPointers() {
        // An empty ByteArray is handed to CryptoKit as a NULL pointer with count 0, so the
        // valid-empty path never touches the buffers the non-empty path does.
        val key = ByteArray(32) { it.toByte() }

        val sealedEmpty = AppleAesGcm.encrypt(key, ByteArray(0), authenticatedData = null)
        assertEquals(
            AppleAesGcm.NONCE_SIZE_BYTES + AppleAesGcm.TAG_SIZE_BYTES,
            sealedEmpty.size,
        )
        assertContentEquals(ByteArray(0), AppleAesGcm.decrypt(key, sealedEmpty, null))

        // Empty AAD and absent AAD must seal identically, or an entry written one way stops
        // reading the other.
        val sealedEmptyAad = AppleAesGcm.encrypt(key, "x".encodeToByteArray(), ByteArray(0))
        assertContentEquals("x".encodeToByteArray(), AppleAesGcm.decrypt(key, sealedEmptyAad, null))
    }
}
