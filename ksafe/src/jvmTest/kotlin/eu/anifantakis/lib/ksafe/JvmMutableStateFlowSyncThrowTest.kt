package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Locks in: an `asMutableStateFlow` write whose persist fails synchronously, on the caller's own
 * thread, leaves nothing optimistic behind. The core serializes before it creates anything that
 * could report a failure, so the asynchronous failure callback never fires here and the value
 * already published to every collector would otherwise outlive the failure for the whole session.
 *
 * @see JvmStateFlowLockedDeviceRollbackTest for the asynchronous half — a commit that fails later
 */
class JvmMutableStateFlowSyncThrowTest {

    private companion object {
        const val KEY = "amount"
        const val DEFAULT = 0.0
        const val STORED = 1.0

        /**
         * KSafe's own `Json` enables `allowSpecialFloatingPointValues`; kotlinx's default rejects
         * them while serializing, which is the deterministic synchronous failure these tests need.
         */
        val STRICT_JSON = KSafeConfig(json = Json { ignoreUnknownKeys = true })
        val UNWRITABLE = Double.POSITIVE_INFINITY
        val MODE = KSafeWriteMode.Encrypted()
    }

    private lateinit var fileName: String

    private fun seededKSafe(policy: KSafeMemoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT): KSafe {
        fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, memoryPolicy = policy, config = STRICT_JSON)
        runBlocking { ksafe.put(KEY, STORED, MODE) }
        return ksafe
    }

    private fun KSafe.amountFlow(scope: CoroutineScope): MutableStateFlow<Double> =
        asMutableStateFlow(DEFAULT, scope, key = KEY, mode = MODE)
            .getValue(null, ::probeProperty)

    @Test
    fun set_whosePersistThrowsSynchronously_propagatesAndKeepsTheDurableValue() =
        setThrowsSynchronously(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun set_whosePersistThrowsSynchronously_underTheEncryptedPolicy_reReadsThroughADecrypt() =
        setThrowsSynchronously(KSafeMemoryPolicy.ENCRYPTED)

    private fun setThrowsSynchronously(policy: KSafeMemoryPolicy) {
        val ksafe = seededKSafe(policy)
        val scope = CoroutineScope(SupervisorJob())
        try {
            val flow = ksafe.amountFlow(scope)
            assertEquals(STORED, flow.value, "sanity: the flow starts in sync with storage")

            assertFailsWith<SerializationException>("misuse must stay loud") {
                flow.value = UNWRITABLE
            }

            assertEquals(
                STORED, flow.value,
                "the write never reached storage, so the flow must not keep showing it",
            )
            assertEquals(
                STORED, (flow as KSafeMutableStateFlow<Double>).lastSyncedValue,
                "and the synced baseline must stay on the durable value",
            )
            assertEquals(STORED, ksafe.getDirect(KEY, DEFAULT), "sanity: storage never changed")
        } finally {
            scope.cancel()
            ksafe.close()
        }
    }

    @Test
    fun compareAndSet_whosePersistThrowsSynchronously_propagatesAndKeepsTheDurableValue() {
        val ksafe = seededKSafe()
        val scope = CoroutineScope(SupervisorJob())
        try {
            val flow = ksafe.amountFlow(scope)
            assertEquals(STORED, flow.value, "sanity: the flow starts in sync with storage")

            assertFailsWith<SerializationException>("misuse must stay loud") {
                flow.compareAndSet(STORED, UNWRITABLE)
            }

            assertEquals(
                STORED, flow.value,
                "compareAndSet publishes before it persists, so it needs the same reconcile as the setter",
            )
            assertEquals(STORED, ksafe.getDirect(KEY, DEFAULT), "sanity: storage never changed")
        } finally {
            scope.cancel()
            ksafe.close()
        }
    }

    /** The failure must settle the flow, not wedge it: the next write has to behave normally. */
    @Test
    fun aLaterWrite_afterASynchronousFailure_persistsNormally() {
        val ksafe = seededKSafe()
        val scope = CoroutineScope(SupervisorJob())
        try {
            val flow = ksafe.amountFlow(scope)
            assertFailsWith<SerializationException> { flow.value = UNWRITABLE }

            val renewed = 3.0
            flow.value = renewed

            assertEquals(renewed, flow.value, "the flow must accept writes again after the failure")
            runBlocking { ksafe.put("barrier", 1, MODE) }
            val reopened = KSafe(fileName = fileName, config = STRICT_JSON)
            try {
                assertEquals(renewed, reopened.getDirect(KEY, DEFAULT), "and they must still reach storage")
            } finally {
                reopened.close()
            }
        } finally {
            scope.cancel()
            ksafe.close()
        }
    }

    /**
     * Every write arms the echo latch and only a matching emission clears it. Left armed, the flow
     * goes deaf to the durable value — the one value storage can still emit after a failed write.
     */
    @Test
    fun anEmissionOfTheDurableValue_afterASynchronousFailure_isNoLongerSuppressed() {
        val ksafe = seededKSafe()
        val scope = CoroutineScope(SupervisorJob())
        try {
            val flow = ksafe.amountFlow(scope) as KSafeMutableStateFlow<Double>
            assertFailsWith<SerializationException> { flow.value = UNWRITABLE }

            flow.simulateStaleClobberForTest(UNWRITABLE)
            flow.updateFromFlow(STORED)

            assertEquals(
                STORED, flow.value,
                "with the latch cleared, the durable value is an ordinary external snapshot again",
            )
        } finally {
            scope.cancel()
            ksafe.close()
        }
    }
}

/** Delegate target; every test passes an explicit key, so the property name is never used. */
private var probeProperty: Double = 0.0
