package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * `resolveFromCache` repopulates the plaintext side cache after a slow
 * synchronous decrypt with what it just decrypted. A put for the same key
 * landing DURING that decrypt has already placed its fresh value in the side
 * cache — the write-back must not overwrite it with the stale pre-write
 * plaintext (under LAZY_PLAIN_TEXT the side cache never expires and the key is
 * dirty forever, so the stale value would be served for the rest of the
 * session; under ENCRYPTED_WITH_TIMED_CACHE for up to the TTL). The write-back
 * is only valid while the primary cache still holds the exact ciphertext that
 * was decrypted. Both side-cache policies are exercised, since cache behavior
 * tested under only one policy misses the others.
 */
class JvmSideCacheWriteBackRaceTest {

    /** Engine whose `decrypt` runs [onDecrypt] (the racing write) before returning
     *  the fixed "old" plaintext — the racing put lands mid-decrypt, deterministically. */
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

        // The racing write: lands while resolveFromCache is mid-decrypt for "k",
        // placing its fresh value into the side cache — which the stale
        // write-back must not overwrite.
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

        // First read decrypts the seeded ciphertext and races the put. Its own
        // result ("old") is a legitimate point-in-time read — irrelevant here.
        ksafe.getDirect("k", "def")

        // Every read AFTER the put must see the put's value. The unguarded
        // write-back left "old" in the never/slow-expiring side cache instead.
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
