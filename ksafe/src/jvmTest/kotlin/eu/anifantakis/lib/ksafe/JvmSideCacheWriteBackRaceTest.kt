package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: resolveFromCache's post-decrypt write-back must not overwrite a fresher value a racing put placed in the side cache mid-decrypt — the write-back is valid only while the primary cache still holds the exact ciphertext that was decrypted (both side-cache policies exercised).
 */
class JvmSideCacheWriteBackRaceTest {

    /** Engine whose `decrypt` runs [onDecrypt] (the racing write) before returning a fixed "old" plaintext. */
    private class RaceEngine : KSafeEncryption {
        @Volatile var onDecrypt: (() -> Unit)? = null
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
            onDecrypt?.invoke()
            onDecrypt = null // race only the first (seeded) decrypt
            return "\"old\"".encodeToByteArray() // JSON for String "old"
        }
        override fun deleteKey(identifier: String) {}
    }

    private fun runScenario(policy: KSafeMemoryPolicy) {
        val engine = RaceEngine()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = policy,   // side-cache policies: the racy write-back path
            lazyLoad = true,         // no auto-collector; we drive updateCache
            testEngine = engine,
        )

        // The racing write lands while resolveFromCache is mid-decrypt for "k", placing its fresh value
        // into the side cache — which the stale write-back must not overwrite.
        engine.onDecrypt = {
            ksafe.putDirect("k", "new", KSafeWriteMode.Encrypted())
        }

        // Hand-seed an encrypted "k" (decrypt yields the stale "old").
        val seeded = mapOf(
            KeySafeMetadataManager.valueRawKey("k") to StoredValue.Text(encodeBase64(byteArrayOf(1))),
            KeySafeMetadataManager.metadataRawKey("k") to
                StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
        )
        runBlocking { ksafe.core.updateCache(seeded) }

        // First read decrypts the seeded ciphertext and races the put; its own "old" result is a
        // legitimate point-in-time read, irrelevant here.
        ksafe.getDirect("k", "def")

        // Every read after the put must see the put's value, not a stale write-back.
        assertEquals(
            "new", ksafe.getDirect("k", "def"),
            "a put landing during a read's decrypt must not have its side-cache value " +
                "overwritten by the stale write-back (policy=$policy)",
        )

        ksafe.close()
    }

    @Test
    fun sideCacheWriteBack_doesNotClobberRacingPut_underLazyPlainText() =
        runScenario(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun sideCacheWriteBack_doesNotClobberRacingPut_underTimedCache() =
        runScenario(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)
}
