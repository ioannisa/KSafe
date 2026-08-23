package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleAesGcm
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Every Apple entry written before 3.1.0 was sealed by the third-party CryptoKit provider that
 * [AppleAesGcm] replaced. These vectors were produced by that provider (KSafe 3.0.0, commit
 * 5c1f2ac) and are decrypted here by the KSafe-owned bridge.
 *
 * A round-trip test cannot catch a framing change — it agrees with itself by construction. This
 * is the only check that fails if the persisted layout ever drifts, and the consequence of that
 * drift is not a broken read: an entry KSafe cannot decrypt is swept as an orphan, so a silent
 * framing change deletes shipped user data.
 */
@OptIn(ExperimentalEncodingApi::class)
class AppleLegacyCiphertextTest {

    private val key = Base64.decode("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=")
    private val plaintext = "KSafe old-format framing vector".encodeToByteArray()
    private val aad = "ksafe.aad.v3|test".encodeToByteArray()

    private val legacyWithoutAad =
        Base64.decode("D0hdvh9WcRTreO+UTqEep7tzurg2E14imrt7TT2aBsExh81j8pA8cpXkJQXNPMMwf5GxeT27BZKwxGw=")
    private val legacyWithAad =
        Base64.decode("84ksnDx1BVuq9ZPpsb8bCKJ8K/Ezqyo1KCkco2vMQE8YGBkJ6LfENLB6fkJlTZ1s28Hym3jMaFKEqmQ=")

    @Test
    fun preRefactorCiphertext_isStillReadable() {
        assertContentEquals(plaintext, AppleAesGcm.decrypt(key, legacyWithoutAad, null))
        assertContentEquals(plaintext, AppleAesGcm.decrypt(key, legacyWithAad, aad))
    }

    @Test
    fun preRefactorCiphertext_isFramedAsNonceCiphertextTag() {
        val overhead = AppleAesGcm.NONCE_SIZE_BYTES + AppleAesGcm.TAG_SIZE_BYTES
        assertEquals(plaintext.size + overhead, legacyWithoutAad.size)
        // Re-sealing under the SAME nonce must reproduce the legacy bytes exactly: proof the
        // ciphertext and tag sit where the old provider put them, not merely that a decrypt
        // happens to succeed.
        val nonce = legacyWithoutAad.copyOfRange(0, AppleAesGcm.NONCE_SIZE_BYTES)
        assertContentEquals(
            legacyWithoutAad,
            AppleAesGcm.encrypt(key, plaintext, authenticatedData = null, nonce = nonce),
        )
    }

    @Test
    fun preRefactorCiphertext_stillFailsClosedOnTheWrongAad() {
        assertFailsWith<IllegalStateException> {
            AppleAesGcm.decrypt(key, legacyWithAad, "ksafe.aad.v3|other".encodeToByteArray())
        }
    }
}
