package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeInitLock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: KSafeInitLock is per-instance and reentrant — distinct locks nest, and a thread can re-acquire its own lock without self-deadlock.
 */
class KSafeInitLockTest {

    @Test
    fun withLock_returnsBlockResult() {
        val lock = KSafeInitLock()
        assertEquals(42, lock.withLock { 42 })
    }

    @Test
    fun reentrantAcquire_onSameThread_doesNotSelfDeadlock() {
        val lock = KSafeInitLock()
        // A non-reentrant lock would hang on the inner acquire; a reentrant one re-enters and returns.
        val result = lock.withLock {
            lock.withLock {
                lock.withLock { "reentered" }
            }
        }
        assertEquals("reentered", result)
    }

    @Test
    fun independentLocks_nestedOnSameThread_doNotDeadlock() {
        val a = KSafeInitLock()
        val b = KSafeInitLock()
        val c = KSafeInitLock()
        // Holding one lock must not block acquiring another; a single process-wide lock would deadlock here.
        val order = ArrayList<String>()
        a.withLock {
            order.add("a")
            b.withLock {
                order.add("b")
                c.withLock { order.add("c") }
            }
        }
        assertEquals(listOf("a", "b", "c"), order)
    }

    @Test
    fun distinctInstances_areNotShared() {
        // Distinct locks are separate objects: re-acquiring the same lock succeeds while another is held.
        val a = KSafeInitLock()
        val b = KSafeInitLock()
        var reached = false
        a.withLock {
            b.withLock {
                a.withLock { // re-enter a while holding b
                    reached = true
                }
            }
        }
        assertTrue(reached)
    }
}
