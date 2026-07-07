package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: clearAll() is serialized with writes on the single-consumer FIFO channel — a write enqueued before it is ordered before the wipe (and cannot resurrect data), while a write issued after it survives.
 */
class JvmClearAllSerializationTest {

    @Test
    fun clearAllWipesAFireAndForgetWriteEnqueuedBeforeIt() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        // clearAll() enqueues its wipe on the SAME FIFO channel, after this put — so
        // the put is ordered before the wipe and must not survive it.
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
