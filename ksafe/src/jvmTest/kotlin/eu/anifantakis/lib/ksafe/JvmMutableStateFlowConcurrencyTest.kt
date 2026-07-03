package eu.anifantakis.lib.ksafe

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * FEEDBACK_4 M12: KSafeMutableStateFlow's write-side echo bookkeeping (lastUserWrite,
 * syncedValue, hasSynced, awaitingWriteEcho) is mutated across separate @Volatile fields.
 * MutableStateFlow permits concurrent writers, so without serialization two setters can
 * interleave — T1 sets lastUserWrite=A, T2 sets lastUserWrite=B and publishes B, T1 then
 * publishes A — leaving `lastUserWrite = B` while the VISIBLE value is A. The echo of A never
 * matches lastUserWrite, so the guard never clears and every later external change is
 * suppressed. The write-side transition now runs under a per-instance lock.
 *
 * This forces the exact interleave deterministically via the [betweenMarkAndPublishForTest]
 * seam: a second writer is launched from inside T1's locked region, right after markUserWrite
 * but before the publish. Under the lock the second writer BLOCKS until T1 finishes, so the
 * tuple stays consistent; without the lock it interleaves and corrupts it. The observable
 * consequence: echoing the visible value must clear the guard so an external change reflects.
 */
class JvmMutableStateFlowConcurrencyTest {

    @Test
    fun concurrentWriter_atMidTransition_isSerialized_soGuardStaysConsistent() {
        val msf = KSafeMutableStateFlow(0) { /* no-op persist */ }
        val t2Done = CountDownLatch(1)

        // Fired once, inside T1's write of 1, between markUserWrite(1) and the publish of 1.
        msf.betweenMarkAndPublishForTest = {
            msf.betweenMarkAndPublishForTest = null // one-shot
            Thread {
                msf.value = 2 // T2's write — must be serialized behind T1's locked region
                t2Done.countDown()
            }.start()
            // Give T2 a real chance to interleave. Under the lock it stays blocked here.
            Thread.sleep(150)
        }

        msf.value = 1 // T1 — fires the hook mid-transition
        assertTrue(t2Done.await(10, TimeUnit.SECONDS), "T2 must complete (no deadlock)")

        // With serialization the last write (T2's) left lastUserWrite == delegate.value == 2, so
        // echoing the visible value clears the guard and the external change below reflects. A
        // corrupted tuple (lastUserWrite=2, visible=1) leaves the guard stuck and suppresses it.
        msf.updateFromFlow(msf.value)
        msf.updateFromFlow(-999)
        assertEquals(-999, msf.value, "an external change must reflect — the guard tuple stayed consistent (M12)")
    }
}
