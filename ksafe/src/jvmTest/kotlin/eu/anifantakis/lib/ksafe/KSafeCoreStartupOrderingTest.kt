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

/**
 * Regression coverage for the 1.x → 2.0 Apple-platform Secure Enclave
 * data-loss bug.
 *
 * **The failure mode this test locks out** — pre-fix,
 * [KSafeCore.startBackgroundCollector] invoked the `migrateAccessPolicy`
 * lambda *before* subscribing to [KSafePlatformStorage.snapshotFlow]. On
 * Apple platforms that lambda is `cleanupOrphanedKeychainEntries`, which
 * starts by calling `storage.snapshot()` to compute the live key set. If
 * that call raced the 1.x → 2.0 path migration in `KSafe.apple.kt` (where
 * the DataStore file gets `moveItemAtPath`-ed from `NSDocumentDirectory`
 * to `NSApplicationSupportDirectory` immediately before DataStore is
 * constructed), it could return an empty snapshot — and the sweep would
 * interpret every Keychain entry as orphaned and call
 * `engine.deleteKeySuspend(...)`. That destroys the SE EC private keys
 * irreversibly: ciphertext that survived the move is then permanently
 * undecryptable because the SE never exports private keys.
 *
 * **The post-fix invariant we assert here**: the cleanup hook MUST run
 * *after* the first `snapshotFlow` emission has populated the cache. We
 * verify that with a fake [KSafePlatformStorage] that records the order
 * of every call (snapshot, snapshotFlow subscription/emission,
 * applyBatch). The fake records into an [AtomicReference]-backed list so
 * the multi-threaded interleaving across `Dispatchers.Default` (where
 * [KSafeCore]'s collector and write scopes run) and the test coroutine
 * is observed safely on every target.
 *
 * If a future refactor moves `migrateAccessPolicy()` back above the
 * snapshot subscription this test will fail with a clear ordering
 * mismatch in the events list.
 */
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
            migrateAccessPolicy = {
                recorder.record("migrateAccessPolicy")
                migrateFired.complete(Unit)
            },
            keyAlias = { it },
            masterAlias = { reqUnlocked -> if (reqUnlocked) "__test_master_locked__" else "__test_master__" },
        )

        // KSafeCore's collector runs on Dispatchers.Default (real
        // threads), not the test dispatcher. `runTest`'s virtual time
        // would advance past any timeout before the Default-thread
        // coroutines had a chance to run, so the test must execute on
        // real time via `runBlocking`. The 10-second timeout is real
        // wall-clock time — generous enough for any reasonable CI
        // runner, tight enough that a regression hangs visibly instead
        // of stalling the whole suite.
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

/**
 * Thread-safe ordered event recorder. Uses an unlimited [Channel] so
 * concurrent writers from any dispatcher push events in arrival order on
 * every KMP target. Channel ordering is FIFO and per-thread `trySend`
 * never blocks on UNLIMITED — so the recorder can be called from
 * non-suspend lambdas (the storage's `snapshotFlow` body) and from
 * suspend boundaries alike.
 */
private class OrderRecorder {
    private val channel = Channel<String>(Channel.UNLIMITED)

    fun record(event: String) {
        // trySend on UNLIMITED never returns failure under normal
        // operation; defensive `getOrThrow()` would only fire if
        // the channel got closed mid-test.
        channel.trySend(event).getOrThrow()
    }

    /**
     * Drain everything queued so far. The channel stays open so a
     * subsequent `record(...)` still works — handy when the test
     * snapshots events at one point, then expects a few more events
     * to land before the suite completes.
     */
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
