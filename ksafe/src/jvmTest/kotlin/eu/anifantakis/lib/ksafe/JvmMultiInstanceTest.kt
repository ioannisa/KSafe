package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: co-existing and close-then-recreated [KSafe] instances on the same file share one ref-counted backend, so no instance trips DataStore's single-instance guard or drops writes.
 */
class JvmMultiInstanceTest {

    @Test
    fun twoLiveInstances_sameFile_bothWritesPersist() = runTest {
        val file = JvmKSafeTest.generateUniqueFileName()
        val a = KSafe(fileName = file, testEngine = FakeEncryption())
        val b = KSafe(fileName = file, testEngine = FakeEncryption())
        a.put("ka", "va")
        b.put("kb", "vb")

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
        // Rapid close→recreate races DataStore's teardown of the prior instance.
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
