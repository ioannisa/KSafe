package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals

/**
 * Device tests for **co-existing [KSafe] instances on the same file** — a configuration the
 * factory deliberately supports (DI re-init, multiple holders). The factory shares ONE
 * DataStore and ONE engine per path, ref-counted, instead of giving each instance a private
 * engine whose in-memory DEK cache diverges from the single persisted wrapped-DEK slot.
 *
 * Pins two invariants:
 *  - a per-engine DEK cache diverging from the one on-disk DEK slot silently loses
 *    data after a `clearAll()` on one instance, or a concurrent first-write race across two;
 *  - closing one instance must not cancel the shared DataStore out from under another.
 *
 * "Restart" is simulated by closing every live instance (ref-count → 0 evicts + tears down
 * the backend) and opening a fresh one, which reads from disk with cold caches.
 */
@RunWith(AndroidJUnit4::class)
class AndroidMultiInstanceTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private fun uniqueFile() = "multi_${System.nanoTime()}"

    @Test
    fun clearAllOnOneInstance_thenWriteOnAnother_survivesRestart() = runBlocking {
        val file = uniqueFile()
        try {
            val a = KSafe(context, fileName = file, lazyLoad = true)
            val b = KSafe(context, fileName = file, lazyLoad = true)

            a.put("token", "v1")                    // establishes the shared DEK
            assertEquals("v1", b.get("token", ""))  // shared DataStore + engine

            a.clearAll()                            // wipes the DEK slot + KEK; clears the shared DEK cache
            b.put("token", "v2")                    // must mint + persist a fresh DEK (shared engine)

            a.close(); b.close()                    // ref-count → 0: evict + tear the backend down

            // Cold restart reads from disk. With a private engine, b's stale DEK cache
            // would encrypt v2 under a DEK that was never re-persisted → lost after restart.
            val c = KSafe(context, fileName = file, lazyLoad = true)
            assertEquals(
                "v2", c.get("token", ""),
                "a post-clearAll write from a co-existing instance must survive restart",
            )
            c.close()
        } finally {
            val cleanup = KSafe(context, fileName = file)
            cleanup.clearAll()
            cleanup.close()
        }
    }

    @Test
    fun concurrentFirstWrites_acrossTwoInstances_allSurviveRestart() = runBlocking {
        val file = uniqueFile()
        try {
            val a = KSafe(context, fileName = file, lazyLoad = true)
            val b = KSafe(context, fileName = file, lazyLoad = true)

            // Concurrent FIRST encrypted writes from both instances. With private engines,
            // each instance would mint its own DEK (last-save-wins on the single slot),
            // leaving values under the losing DEK undecryptable after restart.
            coroutineScope {
                (0 until 8).forEach { i -> launch(Dispatchers.Default) { a.put("a_$i", "av_$i") } }
                (0 until 8).forEach { i -> launch(Dispatchers.Default) { b.put("b_$i", "bv_$i") } }
            }

            a.close(); b.close()

            val c = KSafe(context, fileName = file, lazyLoad = true)
            (0 until 8).forEach { i ->
                assertEquals("av_$i", c.get("a_$i", ""), "a_$i must survive (single shared DEK)")
            }
            (0 until 8).forEach { i ->
                assertEquals("bv_$i", c.get("b_$i", ""), "b_$i must survive (single shared DEK)")
            }
            c.close()
        } finally {
            val cleanup = KSafe(context, fileName = file)
            cleanup.clearAll()
            cleanup.close()
        }
    }

    @Test
    fun closingOneInstance_doesNotBreakAnotherLiveInstance() = runBlocking {
        val file = uniqueFile()
        try {
            val a = KSafe(context, fileName = file, lazyLoad = true)
            val b = KSafe(context, fileName = file, lazyLoad = true)

            a.put("k", "v")
            assertEquals("v", b.get("k", ""))

            a.close() // must not cancel the shared scope out from under b

            // b must still read AND write — the ref-count keeps the shared backend alive
            // while b holds it. The write is the discriminator (a cancelled DataStore scope
            // fails the commit).
            b.put("k2", "v2")
            assertEquals("v2", b.get("k2", ""), "a co-existing instance must keep working after another closes")
            assertEquals("v", b.get("k", ""))
            b.close()
        } finally {
            val cleanup = KSafe(context, fileName = file)
            cleanup.clearAll()
            cleanup.close()
        }
    }
}
