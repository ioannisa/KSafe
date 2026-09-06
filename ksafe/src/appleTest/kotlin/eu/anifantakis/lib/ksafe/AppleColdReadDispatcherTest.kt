package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.value
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.darwin.sysctlbyname
import platform.posix.size_tVar
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * A cold [KSafe.getDirect] parks its thread in `runBlocking` until DataStore answers. On Apple
 * `Dispatchers.Default` is GCD's global queue, capped at `kern.wq_max_constrained_threads`: with
 * the backend on it, that many blocked cold reads leave the read they wait for nowhere to run. A
 * regression fails at the timeout but parks those readers for good, so their count is capped.
 */
@OptIn(ExperimentalForeignApi::class)
class AppleColdReadDispatcherTest {

    private val tempDirs = mutableListOf<String>()

    private fun dir(): String {
        val path = "${NSTemporaryDirectory()}ksafe-cold-read-${Random.nextLong().toULong().toString(36)}"
        NSFileManager.defaultManager.createDirectoryAtPath(
            path, withIntermediateDirectories = true, attributes = null, error = null,
        )
        return path.also { tempDirs += it }
    }

    @AfterTest
    fun cleanup() {
        tempDirs.forEach { NSFileManager.defaultManager.removeItemAtPath(it, error = null) }
        tempDirs.clear()
    }

    /** GCD's per-process cap on global-queue threads; 64 is the kernel default when unreadable. */
    private fun gcdThreadCap(): Int = memScoped {
        val out = alloc<IntVar>()
        val len = alloc<size_tVar>().apply { value = sizeOf<IntVar>().convert() }
        if (sysctlbyname("kern.wq_max_constrained_threads", out.ptr, len.ptr, null, 0u.convert()) == 0) out.value else 64
    }

    // More blocked readers than GCD will ever run at once, so nothing is left for the store.
    private fun saturatingWorkers(): Int = minOf(gcdThreadCap() + 8, 96)

    /** Runs [read] on that many `Dispatchers.Default` coroutines and requires all to finish. */
    private fun everyDefaultThreadReads(read: suspend (Int) -> Unit) {
        val workers = saturatingWorkers()
        // Their own scope, not runBlocking's children: a reader parked for good must not keep the
        // test from returning its verdict.
        val readers = CoroutineScope(Dispatchers.Default + SupervisorJob())
        try {
            runBlocking {
                val reads = List(workers) { i -> readers.async { read(i) } }
                assertNotNull(
                    withTimeoutOrNull(30.seconds) { reads.awaitAll() },
                    "$workers cold getDirect readers on Dispatchers.Default did not finish within 30s: " +
                        "the storage backend has no thread left to answer them",
                )
            }
        } finally {
            readers.cancel()
        }
    }

    @Test
    fun sharedColdInstance_readFromEveryDefaultThread_completes() {
        val ksafe = KSafe(fileName = "cold_shared", directory = dir(), lazyLoad = true, testEngine = FakeEncryption())
        try {
            everyDefaultThreadReads { assertEquals("none", ksafe.getDirect("k", "none")) }
        } finally {
            ksafe.close()
        }
    }

    @Test
    fun coldInstancePerThread_readFromEveryDefaultThread_completes() {
        val d = dir()
        everyDefaultThreadReads { i ->
            val ksafe = KSafe(fileName = "cold_$i", directory = d, lazyLoad = true, testEngine = FakeEncryption())
            try {
                assertEquals("none", ksafe.getDirect("k", "none"))
            } finally {
                ksafe.close()
            }
        }
    }
}
