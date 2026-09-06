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
        // LAZY_PLAIN_TEXT keeps an optimistic plaintext copy in a side cache updateCache doesn't
        // manage, and reads consult it first — rollback must evict it or the phantom lives forever.
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

                // An awaited write is processed within or after the failing batch, and the failure
                // reconcile runs inside that processing — so it is done once this put returns.
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

        // Concurrent, so the coalescer merges all three into one applyBatch.
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
     * XOR engine that fails encrypt on "BAD" and pins the single write consumer inside encrypt on
     * "DECOY" until [releaseGate] opens, so a coalesced batch can be staged in a guaranteed order.
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
        // A batch coalesces same-key ops to the last write, so an earlier delete superseded by a
        // failing encrypted put commits no op at all and the pre-batch value survives on disk. The
        // delete never became durable, so its awaiter must fail rather than report the key gone.
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

            // Park the write consumer in the decoy's encrypt so the next two writes queue undrained.
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
        assertEquals("original", runBlocking { ksafe.get("token", "none") }, "the prior persisted value must survive")

        ksafe.close()
    }

    @Test
    fun failingEncryptedWrite_failsASupersededSameKeyWriteAwaiter() {
        // Twin of the delete case: an earlier put coalesced away by a later failing same-key put was
        // rolled back and never persisted, so its awaiter must fail rather than complete with Unit.
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

            // Same parked batch, coalesced to the late failing op — the early value never encrypts.
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
     * XOR engine that fails once on the marker payload, invoking [onMarkerFailure] (the racing newer
     * write) first, and gates every other encrypt on [commitGate] so that write cannot commit early.
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
     * `dirtyKeys` is a set, not a counter: a newer same-key write during an older write's failing
     * batch is a no-op `add`, so rollback must skip keys whose latest writer is not the failed op.
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

        // The racing newer same-key write, fired while the older write's batch is mid-processing.
        engine.onMarkerFailure = {
            ksafe.putDirect("token", "fresh-v2", KSafeWriteMode.Encrypted())
        }

        assertFailsWith<IllegalStateException> {
            ksafe.put("token", "BAD_v1", KSafeWriteMode.Encrypted())
        }

        try {
            // The newer write is latch-gated in encrypt, so only its optimistic state answers here.
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
