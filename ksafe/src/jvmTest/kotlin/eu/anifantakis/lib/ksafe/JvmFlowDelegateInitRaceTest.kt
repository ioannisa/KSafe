package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CyclicBarrier
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: concurrent first access to a flow property delegate (asMutableStateFlow/asStateFlow/asFlow/asWritableFlow) returns exactly one canonical instance — no duplicate init, no leaked observer coroutine.
 */
class JvmFlowDelegateInitRaceTest {

    private val threads = 8
    private val iterations = 200

    /** N barrier-synchronized threads read the SAME holder's delegated property; every read must observe the same instance. */
    private fun assertSingleInstancePerFirstAccess(newReader: (KSafe, CoroutineScope) -> () -> Any) {
        repeat(iterations) {
            val ksafe = KSafe(fileName = JvmKSafeTest.generateUniqueFileName(), testEngine = FakeEncryption())
            val scope = CoroutineScope(SupervisorJob())
            try {
                val read = newReader(ksafe, scope)
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
                    "concurrent first access to a flow delegate must return exactly one canonical instance",
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
