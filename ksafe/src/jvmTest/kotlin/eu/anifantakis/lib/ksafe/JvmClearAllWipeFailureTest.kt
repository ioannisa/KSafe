package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.serializer
import java.io.IOException
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: a wipe whose `storage.clear()` throws (disk full / EIO during the rewrite) leaves the
 * store exactly as the caller found it — every write sharing the wipe's batch is rolled back
 * instead of staying in RAM as a permanently-dirty phantom, and an entry that survived on disk
 * keeps the engine key that decrypts it.
 */
class JvmClearAllWipeFailureTest {

    /**
     * In-memory storage that can fail its wipe, and can park one batch (the one touching
     * [gateRawKey]) so the test can queue several ops into a single consumer batch.
     */
    private class WipeFailingStorage : KSafePlatformStorage {
        private val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())

        @Volatile var failClear = false
        /** Runs inside [clear], before it throws or wipes — the mid-clearAll seam. */
        @Volatile var beforeClear: (() -> Unit)? = null
        @Volatile private var gateRawKey: String? = null
        val gateEntered = CompletableDeferred<Unit>()
        val gate = CompletableDeferred<Unit>()

        fun parkBatchTouching(rawKey: String) { gateRawKey = rawKey }

        override suspend fun snapshot(): Map<String, StoredValue> = state.value
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = state

        override suspend fun applyBatch(ops: List<StorageOp>) {
            val park = gateRawKey
            if (park != null && ops.any { it.rawKey == park }) {
                gateRawKey = null
                gateEntered.complete(Unit)
                gate.await()
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

        override suspend fun clear() {
            beforeClear?.also { beforeClear = null }?.invoke()
            if (failClear) throw IOException("no space left on device")
            state.value = emptyMap()
        }
    }

    private val cores = mutableListOf<KSafeCore>()

    @AfterTest
    fun tearDown() {
        cores.forEach { it.cancel() }
        cores.clear()
    }

    private fun buildCore(
        storage: KSafePlatformStorage,
        engine: StatefulFakeEncryption,
        policy: KSafeMemoryPolicy,
    ): KSafeCore = KSafeCore(
        storage = storage,
        engineProvider = { engine },
        config = KSafeConfig(),
        memoryPolicy = policy,
        plaintextCacheTtl = 5.seconds,
        resolveKeyStorage = { _, _, _ -> KSafeKeyStorage.SOFTWARE },
        resolveKeyLevel = { _, _, _ -> KSafeProtectionLevel.SOFTWARE },
        lazyLoad = true, // no collector, so nothing else can repair the phantom
        keyAlias = { "p.$it" },
        masterAlias = { req -> if (req) "master_locked" else "master" },
    ).also { cores.add(it) }

    /**
     * Queues a `putDirect` and a failing wipe into ONE consumer batch, on the side of the
     * boundary [clearFirst] selects, and proves the store is untouched afterwards.
     */
    private fun failedWipeRollsBackTheBatch(
        policy: KSafeMemoryPolicy,
        clearFirst: Boolean,
    ) = runBlocking {
        val storage = WipeFailingStorage()
        val engine = StatefulFakeEncryption()
        val core = buildCore(storage, engine, policy)
        val mode = KSafeWriteMode.Encrypted()

        core.putRaw("session", "old", mode, String.serializer())
        assertEquals(
            "old", core.getDirectRaw("session", "", String.serializer()),
            "precondition: the durable value is readable",
        )
        val onDisk = storage.snapshot()[KeySafeMetadataManager.valueRawKey("session")]

        // Park the consumer inside an unrelated batch so the two ops below queue up behind
        // it and are drained into a single batch when it is released.
        storage.parkBatchTouching(KeySafeMetadataManager.valueRawKey("barrier"))
        core.putDirectRaw("barrier", 1, KSafeWriteMode.Plain, Int.serializer())
        withTimeout(10.seconds) { storage.gateEntered.await() }

        storage.failClear = true
        val wipe = CompletableDeferred<Unit>()
        val enqueuePhantom = {
            core.putDirectRaw("session", "phantom", mode, String.serializer())
        }
        if (clearFirst) {
            core.writeChannel.send(KSafeCore.PendingWrite.ClearAll(completion = wipe))
            enqueuePhantom()
        } else {
            enqueuePhantom()
            core.writeChannel.send(KSafeCore.PendingWrite.ClearAll(completion = wipe))
        }
        storage.gate.complete(Unit)

        assertFailsWith<IOException> { withTimeout(10.seconds) { wipe.await() } }

        assertEquals(
            "old", core.getDirectRaw("session", "", String.serializer()),
            "a write batched with a FAILED wipe never reached disk: reads must serve the " +
                "durable value, not the phantom (policy=$policy, clearFirst=$clearFirst)",
        )
        assertFalse(
            core.isUserKeyDirty("session"),
            "the phantom's dirty flag must be released, or every later snapshot merge skips " +
                "the key for the rest of the session",
        )
        assertEquals(
            onDisk, storage.snapshot()[KeySafeMetadataManager.valueRawKey("session")],
            "the failed wipe must leave the entry on disk untouched",
        )
    }

    @Test
    fun failedWipe_rollsBackAWriteBatchedBeforeIt_lazyPlainText() =
        failedWipeRollsBackTheBatch(KSafeMemoryPolicy.LAZY_PLAIN_TEXT, clearFirst = false)

    @Test
    fun failedWipe_rollsBackAWriteBatchedBeforeIt_encrypted() =
        failedWipeRollsBackTheBatch(KSafeMemoryPolicy.ENCRYPTED, clearFirst = false)

    @Test
    fun failedWipe_rollsBackAWriteBatchedBeforeIt_plainText() =
        failedWipeRollsBackTheBatch(KSafeMemoryPolicy.PLAIN_TEXT, clearFirst = false)

    @Test
    fun failedWipe_rollsBackAWriteBatchedBeforeIt_timedCache() =
        failedWipeRollsBackTheBatch(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE, clearFirst = false)

    @Test
    fun failedWipe_rollsBackAWriteBatchedAfterIt() =
        failedWipeRollsBackTheBatch(KSafeMemoryPolicy.ENCRYPTED, clearFirst = true)

    /**
     * The twin of the rollback cases: the wipe SUCCEEDS, and a `putDirect` that landed while it
     * was in flight — its optimistic state set just before the cache wipe erased it — must still
     * be readable and durable once its own batch commits (the owner-gated putIfAbsent repair).
     */
    @Test
    fun putLandingWhileTheWipeIsInFlight_isRepairedAfterASuccessfulClear() = runBlocking {
        val storage = WipeFailingStorage()
        val engine = StatefulFakeEncryption()
        val core = buildCore(storage, engine, KSafeMemoryPolicy.ENCRYPTED)

        core.putRaw("seed", "s", KSafeWriteMode.Encrypted(), String.serializer())

        storage.beforeClear = {
            core.putDirectRaw("fresh", "v", KSafeWriteMode.Encrypted(), String.serializer())
        }
        core.clearAll()

        // FIFO with a single consumer: once this awaited write returns, the racing put has
        // committed and run its post-commit repair.
        core.putRaw("drain", "d", KSafeWriteMode.Plain, String.serializer())

        assertEquals(
            "v", core.getDirectRaw("fresh", "", String.serializer()),
            "a put whose optimistic state the wipe erased must be restored once it commits",
        )
        assertTrue(
            KeySafeMetadataManager.valueRawKey("fresh") in storage.snapshot(),
            "and the repaired value must be the one that reached disk",
        )
    }

    @Test
    fun failedWipe_leavesAHardwareIsolatedEntryDecryptable() = runBlocking {
        val storage = WipeFailingStorage()
        val engine = StatefulFakeEncryption()
        val core = buildCore(storage, engine, KSafeMemoryPolicy.ENCRYPTED)
        val mode = KSafeWriteMode.Encrypted(protection = KSafeEncryptedProtection.HARDWARE_ISOLATED)

        core.putRaw("hwi", "secret", mode, String.serializer())
        assertTrue("p.hwi" in engine.liveAliases(), "precondition: the entry minted a per-entry key")

        storage.failClear = true
        assertFailsWith<IOException> { core.clearAll() }

        assertTrue(
            "p.hwi" in engine.liveAliases(),
            "the wipe failed and the ciphertext survived on disk — destroying its per-entry " +
                "key makes an entry the caller still believes in permanently undecryptable",
        )
        assertEquals(
            "secret",
            buildCore(storage, engine, KSafeMemoryPolicy.ENCRYPTED)
                .getRaw("hwi", "", String.serializer()),
            "the surviving entry must still decrypt from a cold instance",
        )

        storage.failClear = false
        core.clearAll()

        assertFalse("p.hwi" in engine.liveAliases(), "a successful wipe still reclaims the key")
        assertTrue(storage.snapshot().isEmpty(), "a successful wipe still empties the store")
        assertEquals(
            "gone", core.getRaw("hwi", "gone", String.serializer()),
            "and the value is gone",
        )
    }
}
