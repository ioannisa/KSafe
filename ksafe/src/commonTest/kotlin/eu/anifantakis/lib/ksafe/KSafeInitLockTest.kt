package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeInitLock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Contract tests for [KSafeInitLock], the per-delegate init lock behind the flow
 * delegates' double-checked lazy init (FEEDBACK_4 M-G / M11).
 *
 * These pin the two properties the previous Apple implementation violated (M11):
 * it serialized EVERY delegate init on one process-wide, **non-reentrant**
 * busy-spin lock held across the cold-start read. This test encodes the two
 * behaviours that fix requires — and that the old lock failed:
 *
 *  - **Per-instance**: two distinct locks are independent, so a thread already
 *    holding one can acquire another (nesting different locks on one thread must
 *    NOT self-deadlock — under a single global lock it would).
 *  - **Reentrant**: a thread already holding a lock can re-acquire it (nesting
 *    the SAME lock on one thread must NOT self-deadlock — a non-reentrant lock
 *    would hang here, exactly what the old global spin lock did).
 *
 * Single-threaded on purpose: both properties are observable without concurrency,
 * so the test compiles and runs on every target (including single-threaded web).
 * On the old Apple lock these would spin forever; a hang is the "red".
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
        // A non-reentrant lock (the old global spin lock) would hang on the inner
        // acquire. NSRecursiveLock / ReentrantLock re-enter and return.
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
        // Holding one lock must not block acquiring another — the property a single
        // process-wide lock (old Apple impl) violates: b/c would be the SAME lock as
        // a and the inner acquire would deadlock.
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
        // Two locks are genuinely separate objects (not one global singleton): a
        // reentrant re-acquire of the SAME lock succeeds, and the two locks nest.
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
