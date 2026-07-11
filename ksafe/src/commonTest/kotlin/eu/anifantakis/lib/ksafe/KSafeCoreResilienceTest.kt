package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.collectorRetryBackoffMs
import eu.anifantakis.lib.ksafe.internal.drainRemaining
import eu.anifantakis.lib.ksafe.internal.retryingTransientReads
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Locks in the commonMain resilience primitives behind three medium audit fixes:
 * - the snapshot collector resubscribes on a transient read failure instead of dying (M4),
 * - teardown drains queued-but-unprocessed writes rather than leaving awaiters hung (M5),
 * - a plaintext String that collides with the internal null marker round-trips, not to null (M8).
 */
class KSafeCoreResilienceTest {

    // ---- M4: collector survives a transient read failure ---------------------------------

    @Test
    fun retryingTransientReads_resubscribesAfterAThrow() = runTest {
        var subscriptions = 0
        val source = flow {
            subscriptions++
            if (subscriptions == 1) {
                emit(1)
                throw RuntimeException("transient storage read hiccup")
            }
            emit(2)
            emit(3)
        }

        var retries = 0
        val collected = source
            .retryingTransientReads { retries++ }
            .take(3)               // 1 (pre-throw), then 2, 3 after resubscribe — proves recovery
            .toList()

        assertEquals(listOf(1, 2, 3), collected, "the collector must recover the post-failure emissions")
        assertEquals(2, subscriptions, "it must resubscribe exactly once after the throw")
        assertTrue(retries >= 1, "the retry callback must fire")
    }

    @Test
    fun collectorRetryBackoffMs_isExponentialThenCappedAt1s() {
        assertEquals(50L, collectorRetryBackoffMs(0))
        assertEquals(100L, collectorRetryBackoffMs(1))
        assertEquals(200L, collectorRetryBackoffMs(2))
        assertEquals(400L, collectorRetryBackoffMs(3))
        assertEquals(800L, collectorRetryBackoffMs(4))
        assertEquals(1_000L, collectorRetryBackoffMs(5))
        assertEquals(1_000L, collectorRetryBackoffMs(100), "must stay capped, never overflow the shift")
    }

    // ---- M5: teardown drains the write channel without closing it ------------------------

    @Test
    fun drainRemaining_appliesEveryQueuedElementThenStops_withoutClosing() = runTest {
        val channel = Channel<Int>(Channel.UNLIMITED)
        channel.trySend(1); channel.trySend(2); channel.trySend(3)

        val drained = mutableListOf<Int>()
        channel.drainRemaining { drained.add(it) }
        assertEquals(listOf(1, 2, 3), drained)

        // Not closed: the channel is still usable (cancel() relies on this — closing would make
        // an in-flight receive() throw ClosedReceiveChannelException to the uncaught handler).
        assertTrue(channel.trySend(4).isSuccess, "drainRemaining must not close the channel")
        val more = mutableListOf<Int>()
        channel.drainRemaining { more.add(it) }
        assertEquals(listOf(4), more)
    }

    // ---- M8: the null-sentinel escape --------------------------------------------------

    @Test
    fun nullSentinelEscape_roundTripsCollidingStrings_asThemselves() {
        // Ordinary strings are stored verbatim (the escape is a no-op).
        assertEquals("hello", KSafeCore.encodePlainString("hello"))
        assertEquals("hello", KSafeCore.decodePlainString(KSafeCore.encodePlainString("hello")))

        // A plaintext value literally equal to the null marker must NOT be stored as the bare
        // marker (that reads back as null); it is escaped and decodes back to itself.
        val sentinel = KSafeCore.NULL_SENTINEL
        val encoded = KSafeCore.encodePlainString(sentinel)
        assertNotEquals(sentinel, encoded, "the colliding value must be stored in an escaped form")
        assertEquals(sentinel, KSafeCore.decodePlainString(encoded))
    }
}
