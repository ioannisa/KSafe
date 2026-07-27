package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Three commonMain read/write behaviours (JVM exercises the shared logic): a plain→encrypted
 * upgrade evicts the stale plaintext cache slot; a Plain-written primitive read with a complex
 * @Serializable type returns the default instead of throwing; and an encrypted (default-mode)
 * write of a special float round-trips.
 */
class JvmMediumFixesTest {

    private val tracked = mutableListOf<KSafe>()
    private var counter = 0
    private fun uniqueName(): String = "medfix${System.nanoTime()}_${counter++}"
    private fun newKSafe(): KSafe =
        KSafe(fileName = uniqueName(), testEngine = FakeEncryption()).also { tracked += it }

    @AfterTest
    fun tearDown() {
        tracked.forEach { runCatching { it.close() } }
        tracked.clear()
    }

    @Serializable
    data class Profile(val id: Int = 0, val name: String = "")

    @Test
    fun plainToEncryptedUpgrade_evictsThePlaintextCacheSlot() = runTest {
        val ksafe = newKSafe()
        val key = "token"

        ksafe.putDirect(key, "plaintext-secret", KSafeWriteMode.Plain)
        assertTrue(ksafe.core.memoryCache.containsKey(key), "plain slot cached at the bare key")

        ksafe.putDirect(key, "now-encrypted", KSafeWriteMode.Encrypted())

        assertFalse(
            ksafe.core.memoryCache.containsKey(key),
            "the pre-encryption plaintext slot must be evicted, not left resident in RAM",
        )
        assertTrue(ksafe.core.memoryCache.containsKey(KeySafeMetadataManager.legacyEncryptedRawKey(key)))
        assertEquals("now-encrypted", ksafe.getDirect(key, "∅"))
    }

    @Test
    fun encryptedToPlainOverwrite_evictsThePlaintextSideCacheSlot() = runTest {
        // Mirror of the plain→encrypted eviction, reverse direction. Default policy is
        // LAZY_PLAIN_TEXT: an encrypted write caches the decrypted secret in the side cache under
        // legacyEncryptedRawKey(key). Overwriting the key with a Plain write must evict that slot
        // from BOTH caches, or the old secret's plaintext lingers for the process lifetime on a
        // permanently-dirty slot the eviction sweep skips (heap-dump exposure).
        val ksafe = newKSafe()
        val key = "token"
        val encSlot = KeySafeMetadataManager.legacyEncryptedRawKey(key)

        ksafe.put(key, "secretV1", KSafeWriteMode.Encrypted())
        assertTrue(ksafe.core.plaintextCache.containsKey(encSlot), "encrypted write populates the plaintext side cache")

        ksafe.put(key, "placeholder", KSafeWriteMode.Plain)

        assertFalse(ksafe.core.memoryCache.containsKey(encSlot), "encrypted memoryCache slot must be evicted on encrypted→plain")
        assertFalse(ksafe.core.plaintextCache.containsKey(encSlot), "encrypted plaintext side-cache slot must be evicted on encrypted→plain")
        assertTrue(ksafe.core.memoryCache.containsKey(key), "the new plain value is cached at the bare key")
        assertEquals("placeholder", ksafe.getDirect(key, "∅"))
    }

    @Test
    fun plainPrimitiveReadAsComplexType_returnsDefault_notClassCastException() = runTest {
        val ksafe = newKSafe()
        ksafe.put("profile", 42, KSafeWriteMode.Plain)

        val default = Profile(id = -1, name = "default")
        assertEquals(default, ksafe.get("profile", default), "a primitive→complex mismatch must return the default")
    }

    @Test
    fun encryptedDefaultMode_roundTripsSpecialFloats() = runTest {
        val ksafe = newKSafe()

        ksafe.put("nan", Double.NaN)
        ksafe.put("posInf", Double.POSITIVE_INFINITY)
        ksafe.put("negInf", Float.NEGATIVE_INFINITY)

        assertTrue(ksafe.get("nan", 0.0).isNaN(), "encrypted NaN must round-trip, not throw on write")
        assertEquals(Double.POSITIVE_INFINITY, ksafe.get("posInf", 0.0))
        assertEquals(Float.NEGATIVE_INFINITY, ksafe.get("negInf", 0.0f))
    }
}
