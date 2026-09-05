package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Locks in: on web `lazyLoad = true` must not disable the non-suspend read path. The web target
 * has no `runBlocking`, so `ensureCacheReadyBlocking` cannot cold-load; with the snapshot
 * collector suppressed the cache would stay empty for the whole session and every `getDirect` /
 * `by ksafe(...)` read would hand back the caller's default over live persisted data — which a
 * read-modify-write then overwrites.
 */
class WebLazyLoadDirectReadTest {

    // Budget stays under the karma/mocha 2s per-test cap so a failure reports THIS message
    // rather than a framework timeout; the collector needs one event-loop turn.
    private suspend fun awaitTrue(message: String, condition: () -> Boolean) {
        val ok = withContext(Dispatchers.Default) {
            withTimeoutOrNull(1_200) {
                while (!condition()) delay(10)
                true
            }
        } ?: false
        assertTrue(ok, message)
    }

    @Test
    fun lazyLoad_getDirect_readsPersistedValueWithNoSuspendCallFirst() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        val writer = KSafe(fileName = file, lazyLoad = true, testEngine = FakeEncryption())
        writer.awaitCacheReady()
        writer.put("visits", 57, KSafeWriteMode.Plain)
        writer.close()

        val reopened = KSafe(fileName = file, lazyLoad = true, testEngine = FakeEncryption())
        awaitTrue("a lazyLoad web store must still cold-load, so getDirect returns the persisted 57") {
            reopened.getDirect("visits", 0) == 57
        }

        reopened.clearAll()
        reopened.close()
    }

    @Test
    fun lazyLoad_delegateRead_seesPersistedValueInsteadOfItsDefault() = runTest {
        val file = WebKSafeTest.generateUniqueFileName()
        val writer = KSafe(fileName = file, lazyLoad = true, testEngine = FakeEncryption())
        writer.awaitCacheReady()
        writer.put("visits", 57, KSafeWriteMode.Plain)
        writer.close()

        val reopened = KSafe(fileName = file, lazyLoad = true, testEngine = FakeEncryption())
        val visits by reopened(0, key = "visits", mode = KSafeWriteMode.Plain)
        awaitTrue("`by ksafe(...)` on a lazyLoad web store must read 57, not the delegate default") {
            visits == 57
        }

        reopened.clearAll()
        reopened.close()
    }
}
