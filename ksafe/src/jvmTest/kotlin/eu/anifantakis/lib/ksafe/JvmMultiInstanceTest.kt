package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Regression tests for **co-existing / recreated [KSafe] instances on the same file** on JVM
 * (deep-review #51). DataStore (and the JSON-fallback `DataStoreFactory`) refuse two active
 * instances on one file and release a file only once the owning scope completes. Before the
 * factory shared one ref-counted backend per path:
 *  - a second live instance on the same `fileName` tripped "multiple DataStores active for the
 *    same file" inside its collector — swallowed by the cache-load catch — so it silently
 *    returned defaults and dropped its writes; and
 *  - close()-then-recreate raced the teardown and hit the same guard nondeterministically.
 *
 * A [FakeEncryption] keeps these off the real OS key vault — the bug is in the storage layer.
 */
class JvmMultiInstanceTest {

    @Test
    fun twoLiveInstances_sameFile_bothWritesPersist() = runTest {
        val file = JvmKSafeTest.generateUniqueFileName()
        val a = KSafe(fileName = file, testEngine = FakeEncryption())
        val b = KSafe(fileName = file, testEngine = FakeEncryption())
        a.put("ka", "va")
        b.put("kb", "vb") // pre-fix: b's second DataStore on the same file trips the guard → write dropped

        a.close(); b.close()

        // A fresh instance reads from disk. Pre-fix, b's write never persisted.
        val c = KSafe(fileName = file, testEngine = FakeEncryption())
        assertEquals("va", c.get("ka", ""), "first instance's write must persist")
        assertEquals("vb", c.get("kb", ""), "a co-existing same-file instance's write must also persist")
        c.close()
    }

    @Test
    fun closeThenRecreate_sameFile_dataPersists() = runTest {
        val file = JvmKSafeTest.generateUniqueFileName()
        // Rapid close→recreate on the same file. Pre-fix this races DataStore's teardown and
        // intermittently throws "multiple DataStores active for the same file"; the bounded
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
