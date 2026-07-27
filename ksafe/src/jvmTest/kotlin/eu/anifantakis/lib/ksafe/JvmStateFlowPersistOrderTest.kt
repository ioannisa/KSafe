@file:OptIn(
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
    kotlinx.coroutines.InternalCoroutinesApi::class,
    kotlinx.coroutines.ExperimentalForInheritanceCoroutinesApi::class,
)

package eu.anifantakis.lib.ksafe

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: `KSafeMutableStateFlow` enqueues each write's persist INSIDE the same lock that
 * publishes it, so persist order always matches publish order. With the persist outside the
 * lock, two racing writers could publish A→B yet enqueue B→A, making the durable final value
 * the one the visible ordering had discarded — a silent lost update the flow then "healed"
 * to the wrong value.
 */
class JvmStateFlowPersistOrderTest {

    @Test
    fun racingWriter_cannotPersistAheadOfTheWriteItQueuedBehind() {
        val persisted = mutableListOf<String>()
        val msf = KSafeMutableStateFlow("init") { v -> synchronized(persisted) { persisted.add(v) } }

        // Freeze the FIRST writer inside the lock, between its bookkeeping and its
        // publish+persist; the hook must not re-trigger for the second writer.
        val firstWriterInLock = CountDownLatch(1)
        val releaseFirstWriter = CountDownLatch(1)
        val hookUsed = AtomicBoolean(false)
        msf.betweenMarkAndPublishForTest = {
            if (hookUsed.compareAndSet(false, true)) {
                firstWriterInLock.countDown()
                releaseFirstWriter.await(10, TimeUnit.SECONDS)
            }
        }

        val t1 = thread { msf.value = "A" }
        assertTrue(firstWriterInLock.await(10, TimeUnit.SECONDS), "the first writer must reach the lock")

        // The second writer races in while the first is frozen; it must queue behind the lock.
        val t2 = thread { msf.value = "B" }
        t2.join(150)

        synchronized(persisted) {
            assertEquals(
                emptyList(), persisted,
                "no write may reach the persist queue before the write it queued behind has " +
                    "published and persisted — persist must run inside the publish lock",
            )
        }

        releaseFirstWriter.countDown()
        t1.join(10_000)
        t2.join(10_000)

        synchronized(persisted) {
            assertEquals(listOf("A", "B"), persisted, "persist order must match publish order")
            assertEquals(
                msf.value, persisted.last(),
                "the durable final value must be the last visible value",
            )
        }
    }

    @Test
    fun lastPersistedValue_matchesLastVisibleValue_underConcurrentWriters() {
        val persisted = java.util.Collections.synchronizedList(mutableListOf<Int>())
        val msf = KSafeMutableStateFlow(0) { v -> persisted.add(v) }

        val threads = (1..6).map { t ->
            thread { repeat(250) { i -> msf.value = t * 1000 + i } }
        }
        threads.forEach { it.join(30_000) }

        assertTrue(persisted.isNotEmpty(), "writes must have persisted")
        assertEquals(
            msf.value, persisted.last(),
            "after all writers finish, the last persisted value must equal the last visible value",
        )
    }
}
