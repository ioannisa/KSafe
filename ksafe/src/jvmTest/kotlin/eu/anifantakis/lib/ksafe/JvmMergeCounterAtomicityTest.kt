package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import java.util.concurrent.CyclicBarrier
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: every completed merge ticks the merge counter exactly once. A cold reader compares the
 * count taken before its snapshot with the count after its own merge to tell whether another merge
 * landed around it, so two merges that collapse into one tick disarm that check.
 */
class JvmMergeCounterAtomicityTest {

    private val cores = mutableListOf<KSafeCore>()

    @AfterTest
    fun tearDown() {
        cores.forEach { it.cancel() }
        cores.clear()
    }

    private class InMemoryStorage : KSafePlatformStorage {
        private val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())
        override suspend fun snapshot(): Map<String, StoredValue> = state.value
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = state
        override suspend fun applyBatch(ops: List<StorageOp>) {
            state.value = state.value.toMutableMap().also { m ->
                for (op in ops) when (op) {
                    is StorageOp.Put -> m[op.rawKey] = op.value
                    is StorageOp.Delete -> m.remove(op.rawKey)
                }
            }
        }
        override suspend fun clear() { state.value = emptyMap() }
    }

    // lazyLoad: no collector, so the only merges are the ones this test drives.
    private fun buildCore(): KSafeCore = KSafeCore(
        storage = InMemoryStorage(),
        engineProvider = { StatefulFakeEncryption() },
        config = KSafeConfig(),
        memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        plaintextCacheTtl = 5.seconds,
        resolveKeyStorage = { _, _, _ -> KSafeKeyStorage.SOFTWARE },
        resolveKeyLevel = { _, _, _ -> KSafeProtectionLevel.SOFTWARE },
        lazyLoad = true,
        keyAlias = { "p.$it" },
        masterAlias = { req -> if (req) "master_locked" else "master" },
    ).also { cores.add(it) }

    private fun mergeConcurrently(core: KSafeCore, mergers: Int) {
        val barrier = CyclicBarrier(mergers)
        (1..mergers)
            .map {
                thread {
                    runBlocking {
                        barrier.await()
                        core.updateCache(emptyMap())
                    }
                }
            }
            .forEach { it.join() }
    }

    @Test
    fun twoConcurrentMerges_advanceTheCounterByTwo() {
        val core = buildCore()
        repeat(400) { round ->
            val before = core.mergeSequence.get()
            mergeConcurrently(core, mergers = 2)
            assertEquals(
                before + 2,
                core.mergeSequence.get(),
                "round $round: two merges completed but the counter advanced by " +
                    "${core.mergeSequence.get() - before}, so a cold reader cannot see one of them",
            )
        }
    }

    @Test
    fun everyConcurrentMerge_ticksTheCounterOnce() {
        val core = buildCore()
        val mergers = 8
        val rounds = 100
        repeat(rounds) { mergeConcurrently(core, mergers) }
        assertEquals(
            mergers * rounds,
            core.mergeSequence.get(),
            "merges were lost from the counter",
        )
    }
}
