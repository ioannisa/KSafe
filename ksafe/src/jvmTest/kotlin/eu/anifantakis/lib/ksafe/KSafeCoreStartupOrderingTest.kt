package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Locks in: startBackgroundCollector runs migrateAccessPolicy only AFTER the first snapshotFlow emission has populated the cache — on Apple platforms, running it early would let the orphan-Keychain sweep observe an empty snapshot and irreversibly delete Secure Enclave keys. */
class KSafeCoreStartupOrderingTest {

    private var core: KSafeCore? = null

    @AfterTest
    fun tearDown() {
        core?.cancel()
        core = null
    }

    @Test
    fun migrateAccessPolicyRunsAfterFirstSnapshotFlowEmission() = runBlocking {
        val recorder = OrderRecorder()
        val migrateFired = CompletableDeferred<Unit>()
        val fakeStorage = OrderTrackingStorage(recorder)

        core = KSafeCore(
            storage = fakeStorage,
            engineProvider = { FakeEncryption() },
            config = KSafeConfig(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            plaintextCacheTtl = 5.seconds,
            resolveKeyStorage = { _, _ -> KSafeKeyStorage.SOFTWARE },
            resolveKeyLevel = { _, _ -> KSafeProtectionLevel.SOFTWARE },
            migrateAccessPolicy = {
                recorder.record("migrateAccessPolicy")
                migrateFired.complete(Unit)
            },
            keyAlias = { it },
            masterAlias = { reqUnlocked -> if (reqUnlocked) "__test_master_locked__" else "__test_master__" },
        )

        // The collector runs on Dispatchers.Default (real threads), so runTest's virtual clock
        // can't drive it — use runBlocking with a real wall-clock timeout that hangs visibly on regression.
        withTimeout(10_000L) { migrateFired.await() }

        val events = recorder.snapshot()

        val emitIdx = events.indexOf("snapshotFlow.emit")
        val migrateIdx = events.indexOf("migrateAccessPolicy")

        assertTrue(
            emitIdx >= 0,
            "Expected the fake storage to have emitted from snapshotFlow at least once. " +
                "Events: $events",
        )
        assertTrue(
            migrateIdx >= 0,
            "Expected migrateAccessPolicy to have been invoked. Events: $events",
        )
        assertTrue(
            emitIdx < migrateIdx,
            "REGRESSION: migrateAccessPolicy fired BEFORE the first snapshotFlow emission. " +
                "On Apple platforms this would let cleanupOrphanedKeychainEntries observe " +
                "an empty snapshot during a 1.x → 2.0 path migration race, deleting all " +
                "Keychain entries (including SE EC private keys, irreversibly). " +
                "Events: $events",
        )
    }
}

/** Thread-safe FIFO event recorder over an UNLIMITED channel: safe to call from any dispatcher and from non-suspend lambdas. */
private class OrderRecorder {
    private val channel = Channel<String>(Channel.UNLIMITED)

    fun record(event: String) {
        // trySend on UNLIMITED never fails unless the channel is closed mid-test.
        channel.trySend(event).getOrThrow()
    }

    /** Drains everything queued so far; the channel stays open so later records still work. */
    fun snapshot(): List<String> {
        val out = mutableListOf<String>()
        while (true) {
            val r = channel.tryReceive()
            if (r.isFailure) return out
            r.getOrNull()?.let(out::add)
        }
    }
}

private class OrderTrackingStorage(
    private val recorder: OrderRecorder,
) : KSafePlatformStorage {

    override suspend fun snapshot(): Map<String, StoredValue> {
        recorder.record("snapshot()")
        return emptyMap()
    }

    override fun snapshotFlow(): Flow<Map<String, StoredValue>> = flow {
        recorder.record("snapshotFlow.subscribed")
        recorder.record("snapshotFlow.emit")
        emit(emptyMap())
    }

    override suspend fun applyBatch(ops: List<StorageOp>) {
        recorder.record("applyBatch(${ops.size})")
    }

    override suspend fun clear() {
        recorder.record("clear()")
    }
}
