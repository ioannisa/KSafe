package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Locks in: a failing encrypt in a coalesced batch is isolated — unrelated writes survive and the failed write's optimistic value is rolled back. */
class JvmBatchFailureIsolationTest {

    /**
     * XOR [FakeEncryption] whose `encrypt` throws when the plaintext contains [failMarker].
     * Keying failure off the payload (not the alias) fails one DEFAULT key while its
     * master-alias siblings still succeed.
     */
    private class MarkerFailEncryption(private val failMarker: String) : KSafeEncryption {
        private val xor = FakeEncryption()
        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
        ): ByteArray {
            if (data.decodeToString().contains(failMarker)) {
                throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked. (test)")
            }
            return xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }

        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray =
            xor.decrypt(identifier, data)

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    @Test
    fun failedEncryptedWrite_isRolledBack_readReturnsDefaultNotPhantom() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = MarkerFailEncryption("BAD"),
        )

        val ex = assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted())
        }
        assertTrue(
            ex.message?.contains("device is locked", ignoreCase = true) == true,
            "the awaiting caller must receive the encrypt failure; was: ${ex.message}",
        )

        assertEquals(
            "none", ksafe.get("token", "none"),
            "a failed write must be rolled back — reads fall back to the default",
        )

        ksafe.close()
    }

    @Test
    fun failedWrite_doesNotClobberPriorPersistedValue() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = MarkerFailEncryption("BAD"),
        )

        ksafe.put("token", "good_secret", KSafeWriteMode.Encrypted())
        assertEquals("good_secret", ksafe.get("token", "none"))

        assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted())
        }
        assertEquals(
            "good_secret", ksafe.get("token", "none"),
            "a failed overwrite must restore the previously persisted value, not the default or the phantom",
        )

        ksafe.close()
    }

    @Test
    fun failedOverwrite_underLazyPlainTextSideCache_restoresPriorValue() = runTest {
        // LAZY_PLAIN_TEXT keeps an optimistic plaintext copy in the side cache that
        // updateCache doesn't manage; on an overwrite, reads consult it first, so the
        // rollback must evict it or the phantom is served all session (LAZY never expires).
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
            testEngine = MarkerFailEncryption("BAD"),
        )

        ksafe.put("token", "good_secret", KSafeWriteMode.Encrypted())
        assertEquals("good_secret", ksafe.get("token", "none"))

        assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted())
        }
        assertEquals(
            "good_secret", ksafe.get("token", "none"),
            "rollback must evict the optimistic plaintext side-cache entry; the prior value must survive",
        )
        // getDirect goes through the same side cache synchronously — also clean.
        assertEquals("good_secret", ksafe.getDirect("token", "none"))

        ksafe.close()
    }

    @Test
    fun failedOverwrite_underTimedCache_restoresPriorValue_notPhantom() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE,
            testEngine = MarkerFailEncryption("BAD"),
        )

        ksafe.put("token", "good_secret", KSafeWriteMode.Encrypted())
        assertEquals("good_secret", ksafe.get("token", "none"))

        assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted())
        }
        assertEquals(
            "good_secret", ksafe.get("token", "none"),
            "failed overwrite must restore the prior value in the side cache, not the phantom",
        )

        ksafe.close()
    }

    @Test
    fun oneFailingEncrypt_doesNotDropUnrelatedKeysInTheSameBatch() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = MarkerFailEncryption("BAD"),
        )

        // Concurrent writes so the coalescer merges them into one applyBatch: a bad
        // encrypted key, a good encrypted key (shares the master alias), and a plain key.
        coroutineScope {
            launch {
                runCatching { ksafe.put("bad", "BAD_value", KSafeWriteMode.Encrypted()) }
            }
            launch { ksafe.put("goodEnc", "good_enc_value", KSafeWriteMode.Encrypted()) }
            launch { ksafe.put("goodPlain", "good_plain_value", KSafeWriteMode.Plain) }
        }

        assertEquals("good_enc_value", ksafe.get("goodEnc", "missing"))
        assertEquals("good_plain_value", ksafe.get("goodPlain", "missing"))
        assertEquals("missing", ksafe.get("bad", "missing"))

        ksafe.close()
    }

    /**
     * XOR engine that fails encrypt on "BAD" and pins the single write consumer inside
     * encrypt on "DECOY" until [releaseGate] opens — letting the test stage a coalesced
     * batch with a guaranteed op order while the consumer is parked.
     */
    private class PinFailEncryption : KSafeEncryption {
        private val xor = FakeEncryption()
        val decoyPinned = CountDownLatch(1)
        val releaseGate = CountDownLatch(1)
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray {
            val s = data.decodeToString()
            if (s.contains("DECOY")) { decoyPinned.countDown(); releaseGate.await() }
            else if (s.contains("BAD")) throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked. (test)")
            return xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray =
            xor.decrypt(identifier, data)
        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    @Test
    fun failingEncryptedWrite_doesNotContaminate_aSupersededSameKeyDeleteAwaiter() {
        // A batch coalesces same-key ops to the LAST write. When an earlier delete("token")
        // is superseded by a later encrypted put that fails to encrypt, only the failing
        // op's awaiter gets the keystore exception; the superseded delete did no encryption,
        // so its awaiter must complete normally, not be cross-contaminated.
        val engine = PinFailEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )

        var deleteResult: Result<Unit>? = null
        var putResult: Result<Unit>? = null
        runBlocking {
            // A prior persisted value, so a spurious rollback would be observable.
            ksafe.put("token", "original", KSafeWriteMode.Encrypted())
            assertEquals("original", ksafe.get("token", "none"))

            // Park the single write consumer inside the decoy's encrypt so the next two
            // writes queue in the channel without being drained yet.
            val decoyJob = launch(Dispatchers.IO) { runCatching { ksafe.put("decoy", "DECOY_v", KSafeWriteMode.Encrypted()) } }
            engine.decoyPinned.await()

            // Dispatchers.Unconfined runs each launch eagerly up to its first suspension
            // (the await after the synchronous send), so delete's send strictly precedes
            // put's — both land in the same parked batch with the failing put as the final op.
            val delJob = launch(Dispatchers.Unconfined) { deleteResult = runCatching { ksafe.delete("token") } }
            val putJob = launch(Dispatchers.Unconfined) { putResult = runCatching { ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted()) } }

            engine.releaseGate.countDown() // consumer finishes the decoy, then drains [delete, put]
            decoyJob.join(); delJob.join(); putJob.join()
        }

        assertTrue(
            deleteResult!!.isSuccess,
            "a delete superseded by a failing same-key encrypted put must NOT be failed with the " +
                "encryption exception; was: ${deleteResult!!.exceptionOrNull()?.message}",
        )
        assertTrue(putResult!!.isFailure, "the genuinely-failing encrypted put's awaiter must still receive the exception")
        assertTrue(
            putResult!!.exceptionOrNull()?.message?.contains("device is locked", ignoreCase = true) == true,
            "the failing op's awaiter gets the keystore exception; was: ${putResult!!.exceptionOrNull()?.message}",
        )
        // Both token ops no-op'd (delete superseded, failing put rolled back) → prior value survives.
        assertEquals("original", runBlocking { ksafe.get("token", "none") }, "the prior persisted value must survive")

        ksafe.close()
    }

    /**
     * XOR engine that fails once on the marker payload — invoking [onMarkerFailure] (the
     * racing newer write) first — and gates every non-marker encrypt on [commitGate] so the
     * newer write can't commit before the test asserts on its optimistic state.
     */
    private class RaceFailEncryption(private val failMarker: String) : KSafeEncryption {
        private val xor = FakeEncryption()
        @Volatile var onMarkerFailure: (() -> Unit)? = null
        val commitGate = java.util.concurrent.CountDownLatch(1)

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
        ): ByteArray {
            if (data.decodeToString().contains(failMarker)) {
                onMarkerFailure?.invoke()
                onMarkerFailure = null
                throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked. (test)")
            }
            commitGate.await()
            return xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }

        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray =
            xor.decrypt(identifier, data)

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    /**
     * `dirtyKeys` is a set, not a counter: a newer same-key write issued while an older
     * write's batch is failing is a no-op `add`, so rollback must skip a key whose latest
     * writer is no longer the failed op, or it clobbers the newer acknowledged write.
     */
    @Test
    fun failedWriteRollback_doesNotClobber_aNewerWriteToTheSameKey() = runTest {
        val engine = RaceFailEncryption("BAD")
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            lazyLoad = true, // no background collector — nothing heals a wrong rollback
            testEngine = engine,
        )

        // The racing newer same-key write, fired from inside the older write's failing
        // encrypt — i.e. while its batch is mid-processing.
        engine.onMarkerFailure = {
            ksafe.putDirect("token", "fresh-v2", KSafeWriteMode.Encrypted())
        }

        assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_v1", KSafeWriteMode.Encrypted())
        }

        try {
            // The newer write hasn't committed (encrypt is latch-gated), so this read is
            // answered purely by its optimistic state — which the rollback must leave intact.
            assertEquals(
                "fresh-v2", ksafe.getDirect("token", "none"),
                "rollback of a failed write must not strip a newer same-key write's optimistic state",
            )
        } finally {
            engine.commitGate.countDown() // release the newer write's commit
        }

        ksafe.close()
    }
}
