package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Locks in: a failing encrypt in a coalesced batch is isolated — unrelated writes survive and the failed write's optimistic value is rolled back. */
class JvmBatchFailureIsolationTest {

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

    private class TokenFlowHolder(ksafe: KSafe, scope: CoroutineScope) {
        val tokenFlow by ksafe.asMutableStateFlow("none", scope, key = "token", mode = KSafeWriteMode.Encrypted())
    }

    @Test
    fun failedFireAndForgetPersist_revertsTheMutableStateFlowToTheDurableValue() {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = MarkerFailEncryption("BAD"),
        )
        val scope = CoroutineScope(SupervisorJob())
        try {
            runBlocking {
                ksafe.put("token", "good_secret", KSafeWriteMode.Encrypted())

                val flow = TokenFlowHolder(ksafe, scope).tokenFlow
                assertEquals("good_secret", flow.value)

                // Optimistic fire-and-forget persist that fails in the write consumer.
                flow.value = "BAD_phantom"

                // An awaited write is processed after (or within) the failing write's batch,
                // and the failure reconcile runs inside that processing — so it has completed
                // by the time this put returns.
                ksafe.put("flush", "x", KSafeWriteMode.Encrypted())

                assertEquals(
                    "good_secret", flow.value,
                    "a failed fire-and-forget persist must revert the StateFlow to the durable " +
                        "value every other read path already serves, not keep the phantom",
                )
                assertEquals("good_secret", ksafe.get("token", "none"))

                // The latch must not stay armed either: a later durable external write reflects.
                ksafe.put("token", "recovered", KSafeWriteMode.Encrypted())
                withTimeout(10_000) { flow.first { it == "recovered" } }
            }
        } finally {
            scope.cancel()
            ksafe.close()
        }
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
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?,    aad: ByteArray?,): ByteArray {
            val s = data.decodeToString()
            if (s.contains("DECOY")) { decoyPinned.countDown(); releaseGate.await() }
            else if (s.contains("BAD")) throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked. (test)")
            return xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray =
            xor.decrypt(identifier, data)
        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    @Test
    fun failingEncryptedWrite_failsASupersededSameKeyDeleteAwaiter() {
        // A batch coalesces same-key ops to the LAST write. When an earlier delete("token") is
        // superseded by a later encrypted put that fails to encrypt, NO storage op is committed for
        // the key, so the pre-batch value survives on disk. The delete therefore never became
        // durable — its awaiter must be FAILED, not acknowledged with success (which would falsely
        // report "the key is gone" while the old value survives), consistent with how a superseded
        // value write is failed.
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
            deleteResult!!.isFailure,
            "a delete superseded by a failing same-key encrypted put must ALSO be failed: no storage " +
                "op removed the key so the old value survives — acknowledging the delete would falsely " +
                "report it gone. Was success.",
        )
        assertTrue(putResult!!.isFailure, "the genuinely-failing encrypted put's awaiter must still receive the exception")
        assertTrue(
            putResult!!.exceptionOrNull()?.message?.contains("device is locked", ignoreCase = true) == true,
            "the failing op's awaiter gets the keystore exception; was: ${putResult!!.exceptionOrNull()?.message}",
        )
        // Neither token op became durable (delete superseded, failing put rolled back) → prior value survives.
        assertEquals("original", runBlocking { ksafe.get("token", "none") }, "the prior persisted value must survive")

        ksafe.close()
    }

    @Test
    fun failingEncryptedWrite_failsASupersededSameKeyWriteAwaiter() {
        // Twin of the delete case, opposite outcome: when an earlier put("token", ...) is coalesced
        // away by a later same-key encrypted put that FAILS to encrypt, the earlier put's value was
        // rolled back and never persisted — so its awaiter must ALSO fail, not be completed with
        // Unit, or a concurrent caller believes its value is durable when it is gone.
        val engine = PinFailEncryption()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )

        var earlyResult: Result<Unit>? = null
        var lateResult: Result<Unit>? = null
        runBlocking {
            ksafe.put("token", "original", KSafeWriteMode.Encrypted())
            assertEquals("original", ksafe.get("token", "none"))

            val decoyJob = launch(Dispatchers.IO) { runCatching { ksafe.put("decoy", "DECOY_v", KSafeWriteMode.Encrypted()) } }
            engine.decoyPinned.await()

            // early put sends first, the failing late put sends second → same parked batch,
            // coalesced to the late failing op (the early value is never encrypted).
            val earlyJob = launch(Dispatchers.Unconfined) { earlyResult = runCatching { ksafe.put("token", "superseded_value", KSafeWriteMode.Encrypted()) } }
            val lateJob = launch(Dispatchers.Unconfined) { lateResult = runCatching { ksafe.put("token", "BAD_secret", KSafeWriteMode.Encrypted()) } }

            engine.releaseGate.countDown()
            decoyJob.join(); earlyJob.join(); lateJob.join()
        }

        assertTrue(
            earlyResult!!.isFailure,
            "a value-write coalesced away by a failing same-key encrypted put must ALSO be failed " +
                "(its value was rolled back, never persisted); was success",
        )
        assertTrue(lateResult!!.isFailure, "the genuinely-failing encrypted put's awaiter must receive the exception")
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
            aad: ByteArray?,
        ): ByteArray {
            if (data.decodeToString().contains(failMarker)) {
                onMarkerFailure?.invoke()
                onMarkerFailure = null
                throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked. (test)")
            }
            commitGate.await()
            return xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        }

        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray =
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
