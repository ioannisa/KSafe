package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.BACKEND_TEARDOWN_TIMEOUT_MS
import eu.anifantakis.lib.ksafe.internal.CLOSE_QUIESCE_TIMEOUT_MS
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.SharedBackendRegistry
import eu.anifantakis.lib.ksafe.internal.SharedStoreBackend
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.serializer
import java.io.File
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: `close()` waits, bounded, for the storage commit already running — and the last
 * release of a shared backend waits for the store's own writer — so a store reopened right after
 * `close()` sees the rewrite instead of racing it. A commit queued behind the running one never
 * starts, and a hung storage cannot hang shutdown.
 */
class JvmCloseQuiesceTest {

    /** In-memory storage that parks inside the batch touching [parkRawKey] until [release]. */
    private class ParkingStorage : KSafePlatformStorage {
        private val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())

        @Volatile var parkRawKey: String? = null
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()

        override suspend fun snapshot(): Map<String, StoredValue> = state.value
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = state

        override suspend fun applyBatch(ops: List<StorageOp>) {
            val park = parkRawKey
            if (park != null && ops.any { it.rawKey == park }) {
                parkRawKey = null
                entered.complete(Unit)
                release.await()
            }
            state.update { cur ->
                val m = cur.toMutableMap()
                for (op in ops) when (op) {
                    is StorageOp.Put -> m[op.rawKey] = op.value
                    is StorageOp.Delete -> m.remove(op.rawKey)
                }
                m
            }
        }

        override suspend fun clear() { state.value = emptyMap() }

        fun holds(userKey: String): Boolean = KeySafeMetadataManager.valueRawKey(userKey) in state.value
    }

    private class TestBackend(scope: CoroutineScope) : SharedStoreBackend(scope)

    private val storage = ParkingStorage()
    private val cores = mutableListOf<KSafeCore>()
    private val gates = mutableListOf<CompletableDeferred<Unit>>()

    @AfterTest
    fun tearDown() {
        storage.release.complete(Unit)
        gates.forEach { it.complete(Unit) }
        cores.forEach { it.cancel() }
        cores.clear()
    }

    private fun buildCore(): KSafeCore = KSafeCore(
        storage = storage,
        engineProvider = { StatefulFakeEncryption() },
        config = KSafeConfig(),
        memoryPolicy = KSafeMemoryPolicy.LAZY_PLAIN_TEXT,
        plaintextCacheTtl = 5.seconds,
        resolveKeyStorage = { _, _, _ -> KSafeKeyStorage.SOFTWARE },
        resolveKeyLevel = { _, _, _ -> KSafeProtectionLevel.SOFTWARE },
        lazyLoad = true,
        keyAlias = { "p.$it" },
        masterAlias = { req -> if (req) "master_locked" else "master" },
    ).also { cores.add(it) }

    /** Fire-and-forget write parked inside its commit, so the consumer is mid-`applyBatch`. */
    private fun parkCommit(core: KSafeCore, userKey: String) {
        storage.parkRawKey = KeySafeMetadataManager.valueRawKey(userKey)
        core.putDirectRaw(userKey, "v", KSafeWriteMode.Plain, String.serializer())
        runBlocking { withTimeout(10.seconds) { storage.entered.await() } }
    }

    /** Runs [block] on its own thread and reports how long it took, in milliseconds. */
    private fun timedOnAnotherThread(block: () -> Unit): CompletableDeferred<Long> {
        val done = CompletableDeferred<Long>()
        thread {
            val started = System.nanoTime()
            runCatching(block)
                .onSuccess { done.complete((System.nanoTime() - started) / 1_000_000) }
                .onFailure { done.completeExceptionally(it) }
        }
        return done
    }

    @Test
    fun close_waitsForTheCommitAlreadyRunning() {
        val core = buildCore()
        parkCommit(core, "k1")

        val closed = timedOnAnotherThread { core.cancel() }
        Thread.sleep(300)
        assertFalse(closed.isCompleted, "close() returned while the commit was still running")

        storage.release.complete(Unit)
        val ms = runBlocking { withTimeout(5.seconds) { closed.await() } }
        assertTrue(storage.holds("k1"), "the running commit must finish before close() returns")
        assertTrue(ms < CLOSE_QUIESCE_TIMEOUT_MS, "close() must return as soon as the commit lands, took ${ms}ms")
    }

    @Test
    fun close_givesUpOnACommitThatNeverFinishes() {
        val core = buildCore()
        parkCommit(core, "k1")

        val started = System.nanoTime()
        core.cancel()
        val ms = (System.nanoTime() - started) / 1_000_000

        assertTrue(ms >= CLOSE_QUIESCE_TIMEOUT_MS - 200, "close() must wait out the bound, returned after ${ms}ms")
        assertTrue(ms < CLOSE_QUIESCE_TIMEOUT_MS + 3_000, "close() must return once the bound passes, took ${ms}ms")
        assertFalse(storage.holds("k1"))
    }

    @Test
    fun close_neverStartsACommitQueuedBehindTheRunningOne() {
        val core = buildCore()
        parkCommit(core, "k1")
        core.putDirectRaw("k2", "v", KSafeWriteMode.Plain, String.serializer())

        val closed = timedOnAnotherThread { core.cancel() }
        while (!core.closing.get()) Thread.sleep(5)
        storage.release.complete(Unit)
        runBlocking { withTimeout(5.seconds) { closed.await() } }

        assertTrue(storage.holds("k1"), "the commit close() waited for must land")
        assertFalse(storage.holds("k2"), "a commit queued behind it must not start once close() has begun")
    }

    /** A child that ignores cancellation, as DataStore's writer does inside a file rewrite. */
    private fun launchUncancellableWriter(backend: TestBackend): Pair<CompletableDeferred<Unit>, CompletableDeferred<Unit>> {
        val gate = CompletableDeferred<Unit>().also { gates.add(it) }
        val finished = CompletableDeferred<Unit>()
        val started = CompletableDeferred<Unit>()
        backend.scope.launch {
            started.complete(Unit)
            withContext(NonCancellable) {
                gate.await()
                finished.complete(Unit)
            }
        }
        runBlocking { withTimeout(5.seconds) { started.await() } }
        return gate to finished
    }

    @Test
    fun lastRelease_waitsForTheStoresWriter() {
        val registry = SharedBackendRegistry<TestBackend>(Dispatchers.IO)
        val backend = registry.acquire("store-a") { TestBackend(it) }
        val (gate, finished) = launchUncancellableWriter(backend)

        val released = timedOnAnotherThread { registry.release("store-a") }
        Thread.sleep(300)
        assertFalse(released.isCompleted, "release() returned while the store's writer was still running")

        gate.complete(Unit)
        val ms = runBlocking { withTimeout(5.seconds) { released.await() } }
        assertTrue(finished.isCompleted, "the writer must have finished before release() returned")
        assertTrue(ms < BACKEND_TEARDOWN_TIMEOUT_MS, "release() must return as soon as the writer finishes, took ${ms}ms")
    }

    @Test
    fun lastRelease_givesUpOnAWriterThatNeverFinishes_andTheNextAcquireStillWorks() {
        val registry = SharedBackendRegistry<TestBackend>(Dispatchers.IO)
        val backend = registry.acquire("store-b") { TestBackend(it) }
        val (gate, _) = launchUncancellableWriter(backend)

        val started = System.nanoTime()
        registry.release("store-b")
        val ms = (System.nanoTime() - started) / 1_000_000
        assertTrue(ms >= BACKEND_TEARDOWN_TIMEOUT_MS - 200, "release() must wait out the bound, returned after ${ms}ms")
        assertTrue(ms < BACKEND_TEARDOWN_TIMEOUT_MS + 3_000, "release() must return once the bound passes, took ${ms}ms")

        gate.complete(Unit)
        val again = registry.acquire("store-b") { TestBackend(it) }
        assertNotSame(backend, again, "a released backend must not be handed out again")
        registry.release("store-b")
    }

    @Test
    fun reopenRightAfterClose_readsTheLastWrite() {
        val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_close_reopen_${System.nanoTime()}").apply { mkdirs() }
        try {
            runBlocking {
                repeat(30) { i ->
                    val fileName = "reopen_$i"
                    val first = KSafe(fileName = fileName, baseDir = tmp)
                    try {
                        first.put("seeded", "v-seed", KSafeWriteMode.Plain)
                    } finally {
                        first.close()
                    }
                    val second = KSafe(fileName = fileName, baseDir = tmp)
                    try {
                        assertEquals("v-seed", second.getDirect("seeded", ""), "iteration $i lost the write across close()")
                    } finally {
                        second.close()
                    }
                }
            }
        } finally {
            tmp.deleteRecursively()
        }
    }
}
