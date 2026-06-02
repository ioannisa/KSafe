package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Regression test for N1: `clearAll()` is serialized with concurrent writes by
 * routing through the single-consumer write channel (FIFO). A write enqueued
 * BEFORE `clearAll()` is therefore ordered before the wipe and can no longer be
 * applied after it and resurrect data; a write issued AFTER it survives.
 *
 * Before the fix, `clearAll()` cleared storage directly, racing the write
 * consumer — a fire-and-forget `putDirect` enqueued just before could land after
 * the wipe.
 */
class JvmClearAllSerializationTest {

    @Test
    fun clearAllWipesAFireAndForgetWriteEnqueuedBeforeIt() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        // Fire-and-forget write, then clearAll(). clearAll() enqueues its wipe on
        // the SAME FIFO channel, after this put — so the put is ordered before the
        // wipe and must not survive it.
        ksafe.putDirect("token", "secret")
        ksafe.clearAll()

        assertEquals(
            "default", ksafe.get("token", "default"),
            "a write enqueued before clearAll() must be wiped, not resurrected",
        )
        ksafe.close()
    }

    @Test
    fun writesAfterClearAllSurvive() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        ksafe.put("seed", "x")
        ksafe.clearAll()
        ksafe.put("after", "kept")

        assertEquals("default", ksafe.get("seed", "default"), "pre-clearAll data must be gone")
        assertEquals("kept", ksafe.get("after", "default"), "post-clearAll write must survive")
        ksafe.close()
    }
}
