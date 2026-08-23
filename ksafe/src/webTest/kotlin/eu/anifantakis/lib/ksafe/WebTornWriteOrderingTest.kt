package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.LocalStorageStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `localStorage` has no transaction API, so a batch is not atomic: a process death between two
 * `setItem` calls commits a prefix of it. The ordering therefore has to choose which half survives,
 * and one choice is unsafe — committing new metadata over a value slot that still holds the PREVIOUS
 * entry's bytes. `isCanonicalValueEncrypted` treats an explicit `p:NONE` as plaintext, so a plain
 * write over an encrypted entry would otherwise hand the old ciphertext back to the caller as its
 * value.
 *
 * These tests state the property over EVERY prefix rather than asserting one op order, so the
 * invariant survives a future reshuffle of the ordering.
 */
class WebTornWriteOrderingTest {

    private val storage = LocalStorageStorage("ksafe_ordering_test.")

    private val userKey = "token"
    private val valueRawKey = KeySafeMetadataManager.valueRawKey(userKey)
    private val metaRawKey = KeySafeMetadataManager.metadataRawKey(userKey)

    /** The op set a canonical entry write emits, mirroring `entryRecordOps`. */
    private fun entryWrite(value: String, metaJson: String) = listOf(
        StorageOp.Put(valueRawKey, StoredValue.Text(value)),
        StorageOp.Put(metaRawKey, StoredValue.Text(metaJson)),
        StorageOp.Delete(userKey),
        StorageOp.Delete(KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX + userKey),
        StorageOp.Delete(KeySafeMetadataManager.LEGACY_PROTECTION_PREFIX + userKey),
    )

    private fun applyPrefix(
        seed: Map<String, String>,
        ordered: List<StorageOp>,
        count: Int,
    ): Map<String, String> {
        val state = seed.toMutableMap()
        for (op in ordered.take(count)) when (op) {
            is StorageOp.Put -> state[op.rawKey] = (op.value as StoredValue.Text).value
            is StorageOp.Delete -> state.remove(op.rawKey)
        }
        return state
    }

    @Test
    fun noPrefixOfAPlainOverwriteLeavesTheOldCiphertextUnderPlainMetadata() {
        val seed = mapOf(
            valueRawKey to "3q2+7w==", // stand-in for the previous entry's ciphertext
            metaRawKey to """{"v":3,"p":"DEFAULT"}""",
        )
        val ordered = storage.orderMetaBeforeValue(
            entryWrite(value = "plain-text-now", metaJson = """{"v":2,"p":"NONE"}""")
        )

        for (i in 0..ordered.size) {
            val state = applyPrefix(seed, ordered, i)
            if (!KeySafeMetadataManager.isCanonicalValueEncrypted(state[metaRawKey])) {
                val stranded = state[valueRawKey]
                assertTrue(
                    stranded == null || stranded == "plain-text-now",
                    "prefix $i commits plaintext metadata while the value slot still holds " +
                        "'$stranded' — a reader would return that to the caller verbatim",
                )
            }
        }
    }

    @Test
    fun noPrefixOfAnEncryptingOverwriteLeavesThePlaintextUnderEncryptedMetadata() {
        // The mirror direction: plain -> encrypted must not strand readable plaintext either.
        val seed = mapOf(
            valueRawKey to "plain-secret",
            metaRawKey to """{"v":2,"p":"NONE"}""",
        )
        val ordered = storage.orderMetaBeforeValue(
            entryWrite(value = "3q2+7w==", metaJson = """{"v":3,"p":"DEFAULT"}""")
        )

        for (i in 0..ordered.size) {
            val state = applyPrefix(seed, ordered, i)
            if (KeySafeMetadataManager.isCanonicalValueEncrypted(state[metaRawKey])) {
                val stranded = state[valueRawKey]
                assertTrue(
                    stranded == null || stranded == "3q2+7w==",
                    "prefix $i commits encrypted metadata while the value slot still holds the " +
                        "old plaintext '$stranded'",
                )
            }
        }
    }

    @Test
    fun theValueSlotIsClearedBeforeAnyMetadataIsCommitted() {
        val ordered = storage.orderMetaBeforeValue(
            entryWrite(value = "v", metaJson = """{"v":2,"p":"NONE"}""")
        )
        val clearsValue = ordered.indexOfFirst { it is StorageOp.Delete && it.rawKey == valueRawKey }
        val writesMeta = ordered.indexOfFirst { it is StorageOp.Put && it.rawKey == metaRawKey }

        assertTrue(clearsValue >= 0, "the batch must remove the value slot it is about to rewrite")
        assertTrue(
            clearsValue < writesMeta,
            "the value slot must be cleared before the new metadata is committed",
        )
    }

    @Test
    fun aBatchWithNoValuePutIsLeftAlone() {
        // Lifecycle-only batches (the key-generation record) must not gain spurious deletes.
        val keygenOnly = listOf(
            StorageOp.Put(
                KeySafeMetadataManager.KEYGEN_RAW_KEY,
                StoredValue.Text("""{"g":2,"ts":1,"r":0}"""),
            )
        )
        val ordered = storage.orderMetaBeforeValue(keygenOnly)

        assertEquals(keygenOnly, ordered)
        assertNull(
            ordered.firstOrNull { it is StorageOp.Delete },
            "a batch that rewrites no value slot must not delete anything",
        )
    }
}
