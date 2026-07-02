package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CyclicBarrier
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * FEEDBACK_4 M-G: the flow property delegates lazily build their flow on FIRST
 * access via an unsynchronized read-check-then-assign on a plain field. Two
 * threads hitting first access concurrently both run the init block, so a losing
 * caller gets a non-canonical instance and (for the observer-backed delegates) a
 * leaked observer coroutine. The delegates now use `@Volatile` + double-checked
 * init under a lock, so concurrent first access returns exactly one canonical flow.
 *
 * The load-bearing check is INSTANCE IDENTITY across N barrier-synchronized
 * threads that all read the SAME holder's delegated property, looped many times to
 * reliably trigger the contended race on the unfixed code (matches the repo's
 * loop-driven race-test style).
 */
class JvmFlowDelegateInitRaceTest {

    private val threads = 8
    private val iterations = 200

    /** [newReader] builds ONE holder (fresh per iteration) and returns a reader that
     *  invokes its delegated property's getValue. N barrier-synchronized threads then
     *  read it concurrently — every thread must observe the SAME instance. */
    private fun assertSingleInstancePerFirstAccess(newReader: (KSafe, CoroutineScope) -> () -> Any) {
        repeat(iterations) {
            val ksafe = KSafe(fileName = JvmKSafeTest.generateUniqueFileName(), testEngine = FakeEncryption())
            val scope = CoroutineScope(SupervisorJob())
            try {
                val read = newReader(ksafe, scope) // one holder → one delegate per iteration
                val barrier = CyclicBarrier(threads)
                val seen = ConcurrentLinkedQueue<Any>()
                val workers = (0 until threads).map {
                    Thread {
                        barrier.await()
                        seen.add(read())
                    }.apply { start() }
                }
                workers.forEach { it.join() }

                val distinct = seen.map { System.identityHashCode(it) }.distinct()
                assertEquals(
                    1, distinct.size,
                    "concurrent first access to a flow delegate must return exactly one canonical instance (M-G)",
                )
            } finally {
                scope.cancel()
                ksafe.close()
            }
        }
    }

    private class MsfHolder(ksafe: KSafe, scope: CoroutineScope) {
        val sf by ksafe.asMutableStateFlow("init", scope, key = "k")
    }

    private class StateFlowHolder(ksafe: KSafe, scope: CoroutineScope) {
        val sf by ksafe.asStateFlow("init", scope, key = "k")
    }

    private class FlowHolder(ksafe: KSafe) {
        val f by ksafe.asFlow("init", key = "k")
    }

    private class WritableFlowHolder(ksafe: KSafe) {
        val wf by ksafe.asWritableFlow("init", key = "k")
    }

    @Test
    fun asMutableStateFlow_concurrentFirstAccess_returnsOneCanonicalInstance() =
        assertSingleInstancePerFirstAccess { ksafe, scope -> MsfHolder(ksafe, scope).let { { it.sf } } }

    @Test
    fun asStateFlow_concurrentFirstAccess_returnsOneCanonicalInstance() =
        assertSingleInstancePerFirstAccess { ksafe, scope -> StateFlowHolder(ksafe, scope).let { { it.sf } } }

    @Test
    fun asFlow_concurrentFirstAccess_returnsOneCanonicalInstance() =
        assertSingleInstancePerFirstAccess { ksafe, _ -> FlowHolder(ksafe).let { { it.f } } }

    @Test
    fun asWritableFlow_concurrentFirstAccess_returnsOneCanonicalInstance() =
        assertSingleInstancePerFirstAccess { ksafe, _ -> WritableFlowHolder(ksafe).let { { it.wf } } }
}
