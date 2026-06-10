package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * `updateCache` must not clobber a write that lands **during** the merge with
 * the OLD on-disk value: mergeability has to be decided from the LIVE
 * `dirtyKeys` right before each merge write, because the actual `memoryCache`
 * write happens well after entry (once the second-pass decrypt round-trips),
 * and dirty flags are never cleared, so a clobbered write would stay stale for
 * the process lifetime. The race is driven deterministically: the racing write
 * is performed from inside the engine's `decrypt`, i.e. precisely while
 * `updateCache`'s second pass is mid-flight for that key.
 */
class JvmCollectorWriteRaceTest {

    /** Engine whose `decrypt` runs [onDecrypt] (the racing write) before returning a
     *  fixed "old" plaintext, simulating a write that lands during the decrypt window. */
    private class RaceEngine : KSafeEncryption {
        @Volatile var onDecrypt: (() -> Unit)? = null
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun decrypt(identifier: String, data: ByteArray): ByteArray {
            onDecrypt?.invoke()
            onDecrypt = null // race only the first (seeded) decrypt
            return "\"old\"".encodeToByteArray() // JSON for String "old"
        }
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun updateCache_doesNotClobber_aWriteThatLandsDuringDecrypt() {
        val engine = RaceEngine()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT, // forces the second-pass decrypt window
            lazyLoad = true,                              // no auto-collector; we drive updateCache
            testEngine = engine,
        )

        // The racing write: lands while updateCache is decrypting the seeded "k".
        engine.onDecrypt = {
            ksafe.putDirect("k", "new", KSafeWriteMode.Encrypted())
        }

        // Hand-seed a snapshot with an encrypted "k" whose decrypt yields the stale "old".
        val seeded = mapOf(
            KeySafeMetadataManager.valueRawKey("k") to StoredValue.Text(encodeBase64(byteArrayOf(1))),
            KeySafeMetadataManager.metadataRawKey("k") to
                StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
        )

        runBlocking { ksafe.core.updateCache(seeded) }

        // The write that raced the decrypt must win — not be reverted to the stale "old".
        assertEquals(
            "new", ksafe.getDirect("k", "def"),
            "a write landing during updateCache's decrypt must not be clobbered by the stale disk value (deep-review #18)",
        )

        ksafe.close()
    }

    /**
     * The live re-check must also cover the `protectionMap`/`encMetaMap`
     * syncs, not just the `memoryCache` merges: a write that CHANGES a key's
     * protection during the merge window (here: encrypted on disk → racing
     * Plain rewrite) must keep its fresh routing metadata, or reads route to
     * the wrong slot for the rest of the session.
     */
    @Test
    fun updateCache_doesNotRevertProtection_ofAWriteThatLandsDuringDecrypt() {
        val engine = RaceEngine()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT, // forces the second-pass decrypt window
            lazyLoad = true,                              // no auto-collector; we drive updateCache
            testEngine = engine,
        )

        // The racing write flips the key's protection: encrypted (on disk) → Plain.
        engine.onDecrypt = {
            ksafe.putDirect("k", "new-plain", KSafeWriteMode.Plain)
        }

        // Hand-seed a snapshot where "k" is encrypted with DEFAULT protection metadata.
        val seeded = mapOf(
            KeySafeMetadataManager.valueRawKey("k") to StoredValue.Text(encodeBase64(byteArrayOf(1))),
            KeySafeMetadataManager.metadataRawKey("k") to
                StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
        )

        runBlocking { ksafe.core.updateCache(seeded) }

        // If the metadata sync reverted protection to the stale "DEFAULT", the read
        // routes to the (empty) encrypted slot and misses the racing plain write —
        // the freshly-written value must stay reachable instead.
        assertEquals(
            "new-plain", ksafe.getDirect("k", "def"),
            "a protection-changing write landing during updateCache must not have its routing metadata reverted (review R3)",
        )

        ksafe.close()
    }
}
