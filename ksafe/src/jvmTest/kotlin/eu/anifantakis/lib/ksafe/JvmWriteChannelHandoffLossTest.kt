package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: a queued write whose awaiting caller can no longer be served is handed a cancellation.
 * A send to a parked consumer passes the element straight into that continuation, so a teardown
 * landing in the hand-off window leaves it in neither the batch nor the channel — only the
 * channel's undelivered-element handler can still fail the caller instead of hanging it forever.
 */
class JvmWriteChannelHandoffLossTest {

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

    @Test
    fun aWriteDroppedInTheHandoffWindow_cancelsItsAwaiter() = runTest {
        val core = buildCore()
        // The library's own consumer is gone; the channel itself stays open, as cancel() leaves it.
        core.cancel()

        val completion = CompletableDeferred<Unit>()
        val queued = KSafeCore.PendingWrite.Delete(
            userKey = "session",
            rawCacheKey = "session",
            writeToken = Any(),
            completion = completion,
        )

        // Park a receiver, hand it the element, then cancel it before its resume runs: kotlinx
        // discards an element already passed to a cancelled receiver.
        val receiver = launch { core.writeChannel.receive() }
        runCurrent()
        core.writeChannel.send(queued)
        receiver.cancel()
        runCurrent()

        assertTrue(
            completion.isCancelled,
            "the write was dropped in the hand-off window and its caller was left awaiting forever",
        )
    }
}
