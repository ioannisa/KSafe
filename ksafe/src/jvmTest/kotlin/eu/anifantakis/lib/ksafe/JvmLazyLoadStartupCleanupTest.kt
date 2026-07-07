package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Locks in: a `lazyLoad = true` instance still runs the one-time startup cleanup (legacy-key sweep and related migrations) on first access, even though the background collector never starts.
 */
class JvmLazyLoadStartupCleanupTest {

    private class RecordingEngine : KSafeEncryption {
        val legacySweepCalled = CompletableDeferred<Unit>()
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun deleteKey(identifier: String) {}
        override suspend fun migrateLegacyKeysSuspend() { legacySweepCalled.complete(Unit) }
    }

    @Test
    fun lazyLoad_stillRunsTheOneTimeStartupCleanup_onFirstAccess() {
        val engine = RecordingEngine()
        val ksafe = KSafe(fileName = JvmKSafeTest.generateUniqueFileName(), lazyLoad = true, testEngine = engine)
        try {
            runBlocking {
                // First access must trigger the one-time cleanup.
                ksafe.get("k", "def")
                val ran = withTimeoutOrNull(5_000) { engine.legacySweepCalled.await(); true } ?: false
                assertTrue(ran, "a lazyLoad instance must run the legacy-key sweep on first access (low)")
            }
        } finally {
            ksafe.close()
        }
    }
}
