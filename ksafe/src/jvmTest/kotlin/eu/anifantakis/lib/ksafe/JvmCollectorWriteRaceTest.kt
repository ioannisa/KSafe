package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: a write that lands during updateCache's second-pass decrypt is not clobbered by the stale on-disk value — neither its value nor its protection/routing metadata reverts — because mergeability is re-decided from the live dirtyKeys just before each merge write.
 */
class JvmCollectorWriteRaceTest {

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

        assertEquals(
            "new", ksafe.getDirect("k", "def"),
            "a write landing during updateCache's decrypt must not be clobbered by the stale disk value",
        )

        ksafe.close()
    }

    /**
     * The live re-check must also cover the protectionMap/encMetaMap syncs, not just memoryCache: a
     * write that CHANGES a key's protection mid-merge (encrypted on disk → racing Plain rewrite) must
     * keep its fresh routing metadata, or reads route to the wrong slot for the rest of the session.
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

        // A reverted protection would route the read to the empty encrypted slot and miss the plain write.
        assertEquals(
            "new-plain", ksafe.getDirect("k", "def"),
            "a protection-changing write landing during updateCache must not have its routing metadata reverted",
        )

        ksafe.close()
    }
}
