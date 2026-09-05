package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: a write that lands between the snapshot merge's dirty check and its cache store keeps
 * its value — the merge stores only while the slot still holds what it observed, so the racing
 * write's optimistic value survives in RAM instead of being pinned under the stale disk value for
 * the rest of the process. Covers all three merge stores (ciphertext, plain, decrypted plaintext)
 * under every memory policy, plus the uncontended merge that must still populate the cache.
 */
class JvmMergeStoreWriteRaceTest {

    private val key = "k"

    /** On-disk state for an encrypted `k` holding [value] under the identity engine. */
    private fun encryptedSeed(value: String): Map<String, StoredValue> = mapOf(
        KeySafeMetadataManager.valueRawKey(key) to
            StoredValue.Text(encodeBase64("\"$value\"".encodeToByteArray())),
        KeySafeMetadataManager.metadataRawKey(key) to StoredValue.Text(
            KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)
        ),
    )

    /** On-disk state for a plain `k` holding [value]. */
    private fun plainSeed(value: String): Map<String, StoredValue> = mapOf(
        KeySafeMetadataManager.valueRawKey(key) to StoredValue.Text(value),
        KeySafeMetadataManager.metadataRawKey(key) to StoredValue.Text(
            KeySafeMetadataManager.buildMetadataJson(null, accessPolicy = null)
        ),
    )

    private fun newKSafe(policy: KSafeMemoryPolicy) = KSafe(
        fileName = JvmKSafeTest.generateUniqueFileName(),
        memoryPolicy = policy,
        plaintextCacheTtl = 60.seconds, // keep the TIMED_CACHE side cache valid for the whole test
        lazyLoad = true,                // no auto-collector; we drive updateCache
        testEngine = IdentityEngine(),
    )

    /** The plaintext the identity engine's on-disk blob for [key] decrypts to. */
    private fun onDiskEncrypted(ksafe: KSafe): String {
        val raw = runBlocking { ksafe.core.storage.snapshot() }[KeySafeMetadataManager.valueRawKey(key)]
        return KSafeBase64.decode((raw as StoredValue.Text).value).decodeToString()
    }

    private fun onDiskPlain(ksafe: KSafe): String {
        val raw = runBlocking { ksafe.core.storage.snapshot() }[KeySafeMetadataManager.valueRawKey(key)]
        return (raw as StoredValue.Text).value
    }

    /** Fires the racing write inside the merge, once, for [key]. */
    private fun armRace(ksafe: KSafe, mode: KSafeWriteMode) {
        ksafe.core.cacheMergeStoreHook = { racedKey ->
            if (racedKey == key) {
                ksafe.core.cacheMergeStoreHook = null
                ksafe.putDirect(key, "new", mode)
            }
        }
    }

    /**
     * Encrypted entry: the ciphertext store (ciphertext-at-rest policies) and the second-pass
     * decrypted-plaintext store (PLAIN_TEXT) are the two arms this drives.
     */
    private fun runEncryptedScenario(policy: KSafeMemoryPolicy) {
        val ksafe = newKSafe(policy)
        armRace(ksafe, KSafeWriteMode.Encrypted())

        runBlocking { ksafe.core.updateCache(encryptedSeed("old")) }

        assertEquals(
            "new", ksafe.getDirect(key, "def"),
            "a put landing between the merge's dirty check and its store must not be pinned " +
                "under the stale disk value (policy=$policy)",
        )

        // FIFO flush: when this suspend put returns, the racing write has fully committed.
        runBlocking { ksafe.put("__flush__", "x", KSafeWriteMode.Plain) }

        assertEquals(
            "new", runBlocking { ksafe.get(key, "def") },
            "the committed value must still read back after the batch settles (policy=$policy)",
        )
        assertEquals(
            "\"new\"", onDiskEncrypted(ksafe),
            "disk must hold the raced write's value (policy=$policy)",
        )

        ksafe.close()
    }

    @Test
    fun mergeStore_doesNotClobberARacingPut_encrypted_underPlainText() =
        runEncryptedScenario(KSafeMemoryPolicy.PLAIN_TEXT)

    @Test
    fun mergeStore_doesNotClobberARacingPut_encrypted_underLazyPlainText() =
        runEncryptedScenario(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun mergeStore_doesNotClobberARacingPut_encrypted_underEncrypted() =
        runEncryptedScenario(KSafeMemoryPolicy.ENCRYPTED)

    @Test
    fun mergeStore_doesNotClobberARacingPut_encrypted_underTimedCache() =
        runEncryptedScenario(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    /** Plain entry: the merge's plain store, which every policy shares. */
    private fun runPlainScenario(policy: KSafeMemoryPolicy) {
        val ksafe = newKSafe(policy)
        armRace(ksafe, KSafeWriteMode.Plain)

        runBlocking { ksafe.core.updateCache(plainSeed("old")) }

        assertEquals(
            "new", ksafe.getDirect(key, "def"),
            "a plain put landing between the merge's dirty check and its store must not be " +
                "pinned under the stale disk value (policy=$policy)",
        )

        runBlocking { ksafe.put("__flush__", "x", KSafeWriteMode.Plain) }

        assertEquals(
            "new", runBlocking { ksafe.get(key, "def") },
            "the committed plain value must still read back after the batch settles (policy=$policy)",
        )
        assertEquals(
            "new", onDiskPlain(ksafe),
            "disk must hold the raced plain write's value (policy=$policy)",
        )

        ksafe.close()
    }

    @Test
    fun mergeStore_doesNotClobberARacingPut_plain_underPlainText() =
        runPlainScenario(KSafeMemoryPolicy.PLAIN_TEXT)

    @Test
    fun mergeStore_doesNotClobberARacingPut_plain_underLazyPlainText() =
        runPlainScenario(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun mergeStore_doesNotClobberARacingPut_plain_underEncrypted() =
        runPlainScenario(KSafeMemoryPolicy.ENCRYPTED)

    @Test
    fun mergeStore_doesNotClobberARacingPut_plain_underTimedCache() =
        runPlainScenario(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    /** No race: the merge must still populate the cache from disk, for both entry kinds. */
    private fun runUncontendedScenario(policy: KSafeMemoryPolicy) {
        val encrypted = newKSafe(policy)
        runBlocking { encrypted.core.updateCache(encryptedSeed("seeded")) }
        assertEquals(
            "seeded", encrypted.getDirect(key, "def"),
            "an uncontended merge must populate the cache from the encrypted entry (policy=$policy)",
        )
        encrypted.close()

        val plain = newKSafe(policy)
        runBlocking { plain.core.updateCache(plainSeed("seeded")) }
        assertEquals(
            "seeded", plain.getDirect(key, "def"),
            "an uncontended merge must populate the cache from the plain entry (policy=$policy)",
        )
        plain.close()
    }

    @Test
    fun mergeStore_uncontended_populatesTheCache_underPlainText() =
        runUncontendedScenario(KSafeMemoryPolicy.PLAIN_TEXT)

    @Test
    fun mergeStore_uncontended_populatesTheCache_underLazyPlainText() =
        runUncontendedScenario(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun mergeStore_uncontended_populatesTheCache_underEncrypted() =
        runUncontendedScenario(KSafeMemoryPolicy.ENCRYPTED)

    @Test
    fun mergeStore_uncontended_populatesTheCache_underTimedCache() =
        runUncontendedScenario(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    /**
     * The encMetaMap arm: a plain rewrite landing mid-merge drops the key's encryption metadata,
     * which the merge must not put back. The first merge populates encMetaMap so the raced second
     * one has a non-null observed value to CAS against — the live case, where a store has already
     * emitted once.
     */
    @Test
    fun metaStore_protectionFlipLandingMidMerge_keepsTheWritesMetadata() {
        val ksafe = newKSafe(KSafeMemoryPolicy.PLAIN_TEXT)
        runBlocking { ksafe.core.updateCache(encryptedSeed("old")) }

        ksafe.core.cacheMergeMetaStoreHook = { racedKey ->
            if (racedKey == key) {
                ksafe.core.cacheMergeMetaStoreHook = null
                ksafe.putDirect(key, "new", KSafeWriteMode.Plain)
            }
        }
        runBlocking { ksafe.core.updateCache(encryptedSeed("old")) }

        assertEquals(
            "new", ksafe.getDirect(key, "def"),
            "the protection flip's value must survive the merge it landed in",
        )

        runBlocking { ksafe.put("__flush__", "x", KSafeWriteMode.Plain) }

        assertEquals("new", runBlocking { ksafe.get(key, "def") }, "and after the batch settles")
        assertNull(
            ksafe.core.encMetaMap[key],
            "the merge must not restore encryption metadata onto a now-plain key",
        )
        assertEquals(
            KeySafeMetadataManager.protectionToLiteral(null), ksafe.core.protectionMap[key],
            "the flipped key's routing metadata must stay plain",
        )

        ksafe.close()
    }
}
