package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: co-existing and close-then-recreated [KSafe] instances on the same file share one ref-counted backend, so no instance trips DataStore's single-instance guard or drops writes.
 */
class JvmMultiInstanceTest {

    @Test
    fun writeAcknowledgedAfterSiblingClearAll_survivesColdReopen() = runTest {
        // The engine's key store must have real lifecycle semantics: with the alias-derived
        // FakeEncryption a wiped key still "decrypts", hiding exactly this loss.
        val file = JvmKSafeTest.generateUniqueFileName()
        val engine = StatefulFakeEncryption()
        val a = KSafe(fileName = file, testEngine = engine)
        val b = KSafe(fileName = file, testEngine = engine)
        a.put("seed", "s")

        a.clearAll()
        b.put("after", "must-survive") // acknowledged after the wipe completed

        a.close(); b.close()
        val c = KSafe(fileName = file, testEngine = engine)
        assertEquals(
            "must-survive", c.get("after", ""),
            "a write acknowledged after a sibling's clearAll must decrypt on a cold reopen",
        )
        c.close()
    }

    @Test
    fun siblingWriteDuringRotation_survivesTheSweep_andColdReopen() = runTest {
        val file = JvmKSafeTest.generateUniqueFileName()
        val engine = StatefulFakeEncryption()
        val a = KSafe(fileName = file, testEngine = engine)
        val b = KSafe(fileName = file, testEngine = engine)
        a.put("k1", "v1")
        b.put("k2", "v2")

        a.rotateKeys()
        b.put("during", "sibling-write") // may land around the sweep; must never lose its key

        assertEquals("v1", a.get("k1", ""))
        assertEquals("v2", b.get("k2", ""))
        a.close(); b.close()

        val c = KSafe(fileName = file, testEngine = engine)
        assertEquals("v1", c.get("k1", ""), "rotated entry must decrypt after reopen")
        assertEquals("v2", c.get("k2", ""), "sibling's entry must decrypt after reopen")
        assertEquals("sibling-write", c.get("during", ""), "a sibling write around rotation must stay decryptable")
        c.close()
    }

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
