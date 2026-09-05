package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Locks in: co-existing KSafe instances on one file share a ref-counted DataStore + engine, so a clearAll or concurrent first-write can't lose data via diverging per-engine DEK caches, and closing one instance doesn't tear the backend from another. */
@RunWith(AndroidJUnit4::class)
class AndroidMultiInstanceTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private fun uniqueFile() = "multi_${System.nanoTime()}"

    /**
     * The value a SIBLING instance reads, once it has caught up.
     *
     * A sibling learns of another instance's write through its own collector on the shared store,
     * so `put` returning means the value is DURABLE — not that the sibling has merged it yet.
     * Reading it outright passes only while the scheduler happens to be idle. The timeout keeps a
     * genuine "sibling never sees it" regression a failure rather than a hang.
     */
    private suspend fun awaitSibling(sibling: KSafe, key: String, expected: String): String =
        withTimeout(10.seconds) { sibling.getFlow(key, "").first { it == expected } }

    @Test
    fun twoInstances_sameFile_shareOneStorage() = runBlocking {
        val file = uniqueFile()
        val a = KSafe(context, fileName = file, lazyLoad = true)
        val b = KSafe(context, fileName = file, lazyLoad = true)
        try {
            // A private storage per instance means a private commit relay, so a commit through one
            // never reaches the other.
            assertSame(a.core.storage, b.core.storage, "same-file instances must share one storage layer")
        } finally {
            a.close()
            b.clearAll(); b.close()
        }
    }

    @Test
    fun writeOnOneInstance_reachesASiblingAlreadyCollecting() = runBlocking {
        val file = uniqueFile()
        val a = KSafe(context, fileName = file, lazyLoad = true)
        val b = KSafe(context, fileName = file, lazyLoad = true)
        try {
            val seen = mutableListOf<String>()
            val collecting = CompletableDeferred<Unit>()
            val observed = CompletableDeferred<Unit>()
            val job = launch(Dispatchers.Default) {
                b.getFlow("k", "").collect {
                    seen += it
                    collecting.complete(Unit)
                    if (it == "v1") observed.complete(Unit)
                }
            }
            collecting.await()

            a.put("k", "v1")

            withTimeout(5.seconds) { observed.await() }
            assertTrue("v1" in seen, "a sibling collector must observe another instance's write")
            job.cancel()
        } finally {
            a.close()
            b.clearAll(); b.close()
        }
    }

    @Test
    fun clearAllOnOneInstance_thenWriteOnAnother_survivesRestart() = runBlocking {
        val file = uniqueFile()
        try {
            val a = KSafe(context, fileName = file, lazyLoad = true)
            val b = KSafe(context, fileName = file, lazyLoad = true)

            a.put("token", "v1")
            assertEquals("v1", awaitSibling(b, "token", "v1"))

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
            assertEquals("v", awaitSibling(b, "k", "v"))

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

    /**
     * Races a sibling `clearAll` (which wipes the shared wrapped-DEK record) against an encrypted
     * write that already captured the DEK, many times. A concurrent cross-instance clearAll winning
     * over an in-flight put is a legitimate last-writer outcome, so the value may be any written `vN`
     * or the default. What must NEVER happen is a crash, a wrong-plaintext, or a foreign/garbage
     * value — that would mean a DEK-less ciphertext was mis-served instead of swept to the default.
     */
    @Test
    fun concurrentClearAllAndEncrypt_neverReadsBackCorrupt() = runBlocking {
        val file = uniqueFile()
        val default = "∅"
        try {
            val a = KSafe(context, fileName = file, lazyLoad = true)
            val b = KSafe(context, fileName = file, lazyLoad = true)
            a.put("token", "v0")

            val written = hashSetOf("v0")
            for (n in 1..80) {
                val v = "v$n"
                written += v
                coroutineScope {
                    launch(Dispatchers.Default) { a.clearAll() }
                    launch(Dispatchers.Default) { b.put("token", v) }
                }
            }
            a.close(); b.close()

            val c = KSafe(context, fileName = file, lazyLoad = true)
            val read = c.get("token", default)
            c.close()
            assertTrue(
                read == default || read in written,
                "concurrent clearAll vs encrypt must read back a written value or the default, " +
                    "never a corrupt/foreign value: got \"$read\"",
            )
        } finally {
            val cleanup = KSafe(context, fileName = file)
            cleanup.clearAll()
            cleanup.close()
        }
    }
}
