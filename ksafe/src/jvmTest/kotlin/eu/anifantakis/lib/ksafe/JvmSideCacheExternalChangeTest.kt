package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.time.Duration.Companion.seconds

/**
 * FEEDBACK_4 H-F: `updateCache` is the only path that merges an EXTERNAL change
 * (another instance/process, or a direct DataStore edit). It updates the primary
 * `memoryCache` but historically never touched the secondary `plaintextCache`.
 * Under `LAZY_PLAIN_TEXT` (the DEFAULT policy) that side cache never expires, so
 * after an external write a reader kept returning the pre-change plaintext
 * forever — `getDirect`/`get` silently diverged from `getFlow`, and
 * read-your-neighbour's-write was broken.
 *
 * These tests drive `updateCache` directly (as the storage collector would) with
 * an identity engine, so the "ciphertext" carried in a snapshot deterministically
 * decrypts back to the value it encodes — letting an external write flip v1→v2.
 */
class JvmSideCacheExternalChangeTest {

    /** Identity engine: ciphertext bytes == JSON-plaintext bytes, so a snapshot's
     *  StoredValue.Text decrypts back to exactly the value it encodes. */
    private class IdentityEngine : KSafeEncryption {
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun deleteKey(identifier: String) {}
    }

    /** The on-disk StoredValue for an encrypted String `value` under the identity engine. */
    private fun cipherFor(value: String): StoredValue.Text =
        StoredValue.Text(encodeBase64("\"$value\"".encodeToByteArray()))

    private fun snapshotFor(value: String): Map<String, StoredValue> = mapOf(
        KeySafeMetadataManager.valueRawKey("k") to cipherFor(value),
        KeySafeMetadataManager.metadataRawKey("k") to
            StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
    )

    private fun runExternalWriteScenario(policy: KSafeMemoryPolicy) {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = policy,          // side-cache policies maintain plaintextCache
            plaintextCacheTtl = 60.seconds, // keep the TIMED_CACHE side cache valid for the whole test
            lazyLoad = true,                // no auto-collector; we drive updateCache ourselves
            testEngine = IdentityEngine(),
        )

        // Initial disk state: k = "v1". First read populates the plaintext side cache.
        runBlocking { ksafe.core.updateCache(snapshotFor("v1")) }
        assertEquals("v1", ksafe.getDirect("k", "def"), "precondition: initial value reads back (policy=$policy)")

        // Another instance/process overwrites k = "v2"; the collector merges it.
        runBlocking { ksafe.core.updateCache(snapshotFor("v2")) }

        // The reader MUST now see the external write. Before the fix the never/slow-
        // expiring side cache kept serving the stale "v1" indefinitely.
        assertEquals(
            "v2", ksafe.getDirect("k", "def"),
            "an external write must invalidate the stale plaintext side cache (H-F, policy=$policy)",
        )

        ksafe.close()
    }

    @Test
    fun externalWrite_invalidatesStaleSideCache_underLazyPlainText() =
        runExternalWriteScenario(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun externalWrite_invalidatesStaleSideCache_underTimedCache() =
        runExternalWriteScenario(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    @Test
    fun externalDelete_evictsPlaintextSideCache_leavingNoLingeringSecret() {
        // Hygiene twin of the update case: an external delete must not leave the
        // deleted secret's plaintext lingering in the never-expiring side cache
        // (the read itself is already safe — resolveFromCache gates on memoryCache —
        // but a deleted secret must not survive in RAM under LAZY_PLAIN_TEXT).
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
            lazyLoad = true,
            testEngine = IdentityEngine(),
        )

        runBlocking { ksafe.core.updateCache(snapshotFor("secret")) }
        assertEquals("secret", ksafe.getDirect("k", "def")) // populate the side cache
        val sideCacheKey = KeySafeMetadataManager.legacyEncryptedRawKey("k")
        // sanity: the side cache now holds the plaintext
        assert(ksafe.core.plaintextCache.containsKey(sideCacheKey)) { "precondition: side cache populated" }

        // Another instance/process deletes k → empty snapshot merged.
        runBlocking { ksafe.core.updateCache(emptyMap()) }

        assertEquals("def", ksafe.getDirect("k", "def"), "a deleted key must read the default")
        assertFalse(
            ksafe.core.plaintextCache.containsKey(sideCacheKey),
            "an external delete must evict the deleted secret's plaintext from the side cache (H-F)",
        )

        ksafe.close()
    }
}
