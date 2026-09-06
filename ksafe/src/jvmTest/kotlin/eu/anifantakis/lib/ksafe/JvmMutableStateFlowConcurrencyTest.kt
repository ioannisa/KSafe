package eu.anifantakis.lib.ksafe

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: KSafeMutableStateFlow serializes concurrent writers, so the echo-guard bookkeeping (lastUserWrite vs the visible value) stays consistent and external changes are never suppressed.
 */
class JvmMutableStateFlowConcurrencyTest {

    @Test
    fun concurrentWriter_atMidTransition_isSerialized_soGuardStaysConsistent() {
        val msf = KSafeMutableStateFlow(0) { /* no-op persist */ }
        val t2Done = CountDownLatch(1)

        // The seam fires inside T1's write, between markUserWrite and the publish, so launching T2
        // there forces the interleave; the sleep gives it a real chance (the lock blocks it).
        msf.betweenMarkAndPublishForTest = {
            msf.betweenMarkAndPublishForTest = null // one-shot
            Thread {
                msf.value = 2
                t2Done.countDown()
            }.start()
            Thread.sleep(150)
        }

        msf.value = 1
        assertTrue(t2Done.await(10, TimeUnit.SECONDS), "T2 must complete (no deadlock)")

        // Echoing the visible value clears the guard only if the tuple stayed consistent,
        // in which case the external change below reflects.
        msf.updateFromFlow(msf.value)
        msf.updateFromFlow(-999)
        assertEquals(-999, msf.value, "an external change must reflect — the guard tuple stayed consistent")
    }
}
