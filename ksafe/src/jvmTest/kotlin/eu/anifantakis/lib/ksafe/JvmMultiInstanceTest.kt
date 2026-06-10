package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Tests for **co-existing / recreated [KSafe] instances on the same file** on
 * JVM. DataStore (and the JSON-fallback `DataStoreFactory`) refuse two active
 * instances on one file and release a file only once the owning scope
 * completes, so the factory must share one ref-counted backend per path:
 * otherwise a second live instance on the same `fileName` silently returns
 * defaults and drops its writes, and close()-then-recreate races the teardown
 * nondeterministically.
 *
 * A [FakeEncryption] keeps these off the real OS key vault — the behavior under
 * test lives in the storage layer.
 */
class JvmMultiInstanceTest {

    @Test
    fun twoLiveInstances_sameFile_bothWritesPersist() = runTest {
        val file = JvmKSafeTest.generateUniqueFileName()
        val a = KSafe(fileName = file, testEngine = FakeEncryption())
        val b = KSafe(fileName = file, testEngine = FakeEncryption())
        a.put("ka", "va")
        b.put("kb", "vb") // a second same-file instance must not trip DataStore's single-instance guard

        a.close(); b.close()

        // A fresh instance reads from disk: both writes must have persisted.
        val c = KSafe(fileName = file, testEngine = FakeEncryption())
        assertEquals("va", c.get("ka", ""), "first instance's write must persist")
        assertEquals("vb", c.get("kb", ""), "a co-existing same-file instance's write must also persist")
        c.close()
    }

    @Test
    fun closeThenRecreate_sameFile_dataPersists() = runTest {
        val file = JvmKSafeTest.generateUniqueFileName()
        // Rapid close→recreate on the same file races DataStore's teardown
        // ("multiple DataStores active for the same file"); the bounded
        // prior-scope await makes it deterministic.
        repeat(20) { i ->
            val ks = KSafe(fileName = file, testEngine = FakeEncryption())
            ks.put("counter", "v$i")
            assertEquals("v$i", ks.get("counter", ""), "value must round-trip within the instance")
            ks.close()
        }
        val reopened = KSafe(fileName = file, testEngine = FakeEncryption())
        assertEquals("v19", reopened.get("counter", ""), "data must persist across close→recreate")
        reopened.close()
    }
}
