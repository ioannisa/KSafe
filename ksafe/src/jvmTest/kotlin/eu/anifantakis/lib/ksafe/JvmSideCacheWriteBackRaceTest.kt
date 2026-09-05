package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: resolveFromCache's post-decrypt write-back must not overwrite a fresher value a racing put placed in the side cache mid-decrypt — the write-back is valid only while the primary cache still holds the exact ciphertext that was decrypted (both side-cache policies exercised), including when the put lands after the guard and before the store.
 */
class JvmSideCacheWriteBackRaceTest {

    /** Identity round-trip that counts decrypts, so a side-cache hit is provable. */
    private class CountingIdentityEngine : KSafeEncryption {
        @Volatile var decrypts = 0

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray = data

        override fun decrypt(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            decrypts++
            return data
        }

        override fun deleteKey(identifier: String) {}
    }

    /** Hand-seeded on-disk state for an encrypted `k` holding [value] under an identity engine. */
    private fun seedFor(value: String): Map<String, StoredValue> = mapOf(
        KeySafeMetadataManager.valueRawKey("k") to
            StoredValue.Text(encodeBase64("\"$value\"".encodeToByteArray())),
        KeySafeMetadataManager.metadataRawKey("k") to
            StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
    )

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

    /**
     * The whole put — primary cache AND side cache — lands after the write-back's guard has
     * passed and before it stores, so the guard alone cannot see it.
     */
    private fun runPostGuardScenario(policy: KSafeMemoryPolicy) {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = policy,
            plaintextCacheTtl = 60.seconds, // keep the TIMED_CACHE side cache valid for the whole test
            lazyLoad = true,
            testEngine = CountingIdentityEngine(),
        )

        runBlocking { ksafe.core.updateCache(seedFor("old")) }

        ksafe.core.sideCacheWriteBackHook = {
            ksafe.core.sideCacheWriteBackHook = null // race only the first read
            ksafe.putDirect("k", "new", KSafeWriteMode.Encrypted())
        }

        // Its own "old" result is a legitimate point-in-time read; what follows is not.
        ksafe.getDirect("k", "def")

        assertEquals(
            "new", ksafe.getDirect("k", "def"),
            "a put landing between the write-back's guard and its store must not be " +
                "pinned over by the stale plaintext (policy=$policy)",
        )

        // FIFO flush: when this suspend put returns, the racing write has fully committed.
        runBlocking { ksafe.put("__flush__", "x", KSafeWriteMode.Plain) }

        assertEquals(
            "new", runBlocking { ksafe.get("k", "def") },
            "the committed value must still read back after the batch settles (policy=$policy)",
        )

        ksafe.close()
    }

    @Test
    fun sideCacheWriteBack_afterGuardRace_doesNotPinStaleValue_underLazyPlainText() =
        runPostGuardScenario(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun sideCacheWriteBack_afterGuardRace_doesNotPinStaleValue_underTimedCache() =
        runPostGuardScenario(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    /** No race: the write-back must still populate the side cache, so a second read never decrypts. */
    private fun runUncontendedScenario(policy: KSafeMemoryPolicy) {
        val engine = CountingIdentityEngine()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = policy,
            plaintextCacheTtl = 60.seconds,
            lazyLoad = true,
            testEngine = engine,
        )

        runBlocking { ksafe.core.updateCache(seedFor("v1")) }

        assertEquals("v1", ksafe.getDirect("k", "def"), "precondition: the seeded value reads back")
        val afterFirstRead = engine.decrypts
        assertTrue(afterFirstRead > 0, "precondition: the first read decrypted (policy=$policy)")
        assertTrue(
            ksafe.core.plaintextCache.containsKey(KeySafeMetadataManager.legacyEncryptedRawKey("k")),
            "an uncontended write-back must populate the side cache (policy=$policy)",
        )

        assertEquals("v1", ksafe.getDirect("k", "def"))
        assertEquals(
            afterFirstRead, engine.decrypts,
            "a second read must be served from the side cache, not decrypted again (policy=$policy)",
        )

        ksafe.close()
    }

    @Test
    fun sideCacheWriteBack_uncontended_populatesTheSideCache_underLazyPlainText() =
        runUncontendedScenario(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun sideCacheWriteBack_uncontended_populatesTheSideCache_underTimedCache() =
        runUncontendedScenario(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)
}
