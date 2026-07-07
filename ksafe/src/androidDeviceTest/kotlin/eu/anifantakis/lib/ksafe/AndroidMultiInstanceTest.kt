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

/** Locks in: co-existing KSafe instances on one file share a ref-counted DataStore + engine, so a clearAll or concurrent first-write can't lose data via diverging per-engine DEK caches, and closing one instance doesn't tear the backend from another. */
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

            a.put("token", "v1")
            assertEquals("v1", b.get("token", ""))

            a.clearAll()
            b.put("token", "v2")

            a.close(); b.close()

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

            // Concurrent FIRST encrypted writes from both instances — private engines would
            // each mint their own DEK (last-save-wins on the single slot) and lose the loser's values.
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

            // The ref-count keeps the backend alive while b holds it; the write is the
            // discriminator (a cancelled DataStore scope fails the commit).
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
