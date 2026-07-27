package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.runBlocking
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: the failure-notifying [KSafe.putDirect] overload — `onWriteFailed` fires when the
 * asynchronous persist fails, after the core has rolled the optimistic cache back to the
 * durable value, and never fires for a successful write. This is the seam the Compose and
 * StateFlow adapters use to reconcile optimistic state after a failed fire-and-forget persist.
 */
class JvmPutDirectFailureCallbackTest {

    @Test
    fun onWriteFailed_firesAfterAsyncFailure_withTheCacheAlreadyRolledBack() {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = MarkerFailEncryption("BAD"),
        )

        val notified = CountDownLatch(1)
        ksafe.putDirect("token", "BAD_secret", KSafeWriteMode.Encrypted()) { notified.countDown() }

        assertTrue(
            notified.await(10, TimeUnit.SECONDS),
            "onWriteFailed must fire for a failed asynchronous persist",
        )
        assertEquals(
            "none", ksafe.getDirect("token", "none"),
            "the optimistic value must be rolled back before the failure callback runs",
        )

        ksafe.close()
    }

    @Test
    fun onWriteFailed_neverFires_forASuccessfulWrite() {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = MarkerFailEncryption("BAD"),
        )

        val notified = CountDownLatch(1)
        ksafe.putDirect("token", "good_secret", KSafeWriteMode.Encrypted()) { notified.countDown() }

        // FIFO flush: when this suspend put returns, the earlier write has fully processed.
        runBlocking { ksafe.put("__flush__", "x", KSafeWriteMode.Plain) }

        assertFalse(notified.await(100, TimeUnit.MILLISECONDS), "a successful write must not notify")
        assertEquals("good_secret", ksafe.getDirect("token", "none"))

        ksafe.close()
    }
}
