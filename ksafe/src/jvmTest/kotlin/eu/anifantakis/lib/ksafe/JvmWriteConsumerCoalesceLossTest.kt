package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import java.io.File
import java.util.concurrent.locks.LockSupport
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Locks in: a write handed to the consumer inside the coalesce window survives the window timer
 * firing first. It used to vanish: a fire-and-forget write lost, a suspend put hung forever.
 */
class JvmWriteConsumerCoalesceLossTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_coalesce_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    @Test
    fun writesLandingOnTheWindowEdge_areNeverDropped() = runBlocking {
        val writes = 500
        val ksafe = KSafe(fileName = "coalesce", baseDir = tmp, testEngine = FakeEncryption())
        val burners = CoroutineScope(Dispatchers.Default + SupervisorJob())
        try {
            // Burners must yield: a never-yielding burner starves the consumer outright,
            // which would hang the final put for the wrong reason.
            repeat(Runtime.getRuntime().availableProcessors() * 2) {
                burners.launch {
                    while (isActive) {
                        val until = System.nanoTime() + 3_000_000L
                        while (System.nanoTime() < until) Thread.onSpinWait()
                        yield()
                    }
                }
            }
            val producer = Thread {
                val rnd = Random(1234)
                for (i in 0 until writes) {
                    ksafe.putDirect("k$i", i, mode = KSafeWriteMode.Plain)
                    LockSupport.parkNanos(rnd.nextLong(100_000L, 20_000_000L))
                }
            }
            producer.start()
            producer.join(60_000)
            assertTrue(!producer.isAlive, "producer stalled")
            withTimeoutOrNull(30_000) { ksafe.put("final", 1) }
                ?: fail("suspend put hung: its write was dropped by the coalesce window")
        } finally {
            burners.cancel()
        }
        ksafe.close()

        val reopened = KSafe(fileName = "coalesce", baseDir = tmp, testEngine = FakeEncryption())
        val missing = (0 until writes).filter { reopened.get("k$it", -1) != it }.map { "k$it" }
        reopened.close()
        assertTrue(missing.isEmpty(), "dropped ${missing.size} of $writes writes: ${missing.take(30)}")
    }
}
