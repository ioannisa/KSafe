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
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: when the rollback's own disk re-merge fails — the same disk fault that failed the
 * write usually blinds the read right after it, and the generation-read failure path IS a failed
 * snapshot read — the failed write's never-persisted optimistic value must not stay in RAM. Under
 * `lazyLoad` nothing else ever repairs it, so reads would serve a phantom (plaintext, in the
 * encrypted slot) for the process lifetime.
 */
class JvmRollbackRemergeFailureTest {

    /** In-memory storage whose reads and writes can be faulted independently. */
    private class FaultyStorage : KSafePlatformStorage {
        private val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())

        /** Number of upcoming [snapshot] calls to fail. */
        @Volatile var failSnapshots = 0

        /** Fails the next [applyBatch]. */
        @Volatile var failNextApplyBatch = false

        /** Whether that write fault also blinds the read that follows it (the common disk case). */
        @Volatile var applyBatchFailureBlindsNextRead = true

        /** Runs inside the failing [snapshot], just before it throws — the mid-rollback seam. */
        @Volatile var beforeSnapshotFailure: (() -> Unit)? = null

        /** Parks the next batch touching this raw key. */
        @Volatile var parkRawKey: String? = null
        val parkEntered = CompletableDeferred<Unit>()
        val parkGate = CompletableDeferred<Unit>()

        override suspend fun snapshot(): Map<String, StoredValue> {
            if (failSnapshots > 0) {
                failSnapshots--
                beforeSnapshotFailure?.also { beforeSnapshotFailure = null }?.invoke()
                throw IOException("simulated snapshot read failure")
            }
            return state.value
        }

        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = state

        override suspend fun applyBatch(ops: List<StorageOp>) {
            if (failNextApplyBatch) {
                failNextApplyBatch = false
                if (applyBatchFailureBlindsNextRead) failSnapshots = 1
                throw IOException("simulated batch write failure")
            }
            val park = parkRawKey
            if (park != null && ops.any { it.rawKey == park }) {
                parkRawKey = null
                parkEntered.complete(Unit)
                parkGate.await()
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
    ).also {
        // The lazy startup sweep would otherwise read the store on a background scope and
        // consume the faults this test aims at the write path.
        it.startupCleanupDone.set(true)
        cores.add(it)
    }

    private val mode = KSafeWriteMode.Encrypted()

    /**
     * Seeds a durable value and returns the core with its cache readied, so the failing write
     * below is an OVERWRITE of something the store really holds.
     */
    private suspend fun seededCore(
        storage: FaultyStorage,
        policy: KSafeMemoryPolicy,
    ): KSafeCore {
        val core = buildCore(storage, StatefulFakeEncryption(), policy)
        core.putRaw("session", "old", mode, String.serializer())
        assertEquals(
            "old", core.getDirectRaw("session", "none", String.serializer()),
            "precondition: the durable value is readable",
        )
        return core
    }

    private suspend fun assertPhantomIsGoneAndDiskWins(
        storage: FaultyStorage,
        core: KSafeCore,
        policy: KSafeMemoryPolicy,
    ) {
        assertEquals(
            "none", core.getDirectRaw("session", "none", String.serializer()),
            "the rollback's re-merge failed, so the never-persisted value must be DROPPED from " +
                "RAM — reads serve the caller's default, never the phantom (policy=$policy)",
        )
        assertFalse(
            core.isUserKeyDirty("session"),
            "and the key must be left mergeable, or no later snapshot can ever repopulate it",
        )

        val epoch = core.clearEpoch.get()
        core.updateCache(storage.snapshot(), epoch)
        assertEquals(
            "old", core.getDirectRaw("session", "none", String.serializer()),
            "once a merge does run, the dropped slot repopulates from disk (policy=$policy)",
        )
    }

    /** (a) The batch write fails and the same fault blinds the rollback's read. */
    private fun failedApplyBatchWithBlindRollback(policy: KSafeMemoryPolicy) = runBlocking {
        val storage = FaultyStorage()
        val core = seededCore(storage, policy)

        storage.failNextApplyBatch = true
        assertFailsWith<IOException> {
            core.putRaw("session", "phantom", mode, String.serializer())
        }

        assertPhantomIsGoneAndDiskWins(storage, core, policy)
    }

    @Test
    fun failedBatchAndBlindRollback_dropsThePhantom_lazyPlainText() =
        failedApplyBatchWithBlindRollback(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun failedBatchAndBlindRollback_dropsThePhantom_encrypted() =
        failedApplyBatchWithBlindRollback(KSafeMemoryPolicy.ENCRYPTED)

    @Test
    fun failedBatchAndBlindRollback_dropsThePhantom_timedCache() =
        failedApplyBatchWithBlindRollback(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    @Test
    fun failedBatchAndBlindRollback_dropsThePhantom_plainText() =
        failedApplyBatchWithBlindRollback(KSafeMemoryPolicy.PLAIN_TEXT)

    /**
     * (b) The generation read that opens an encrypting batch fails — a snapshot-read failure by
     * definition, so the rollback's own re-merge read fails with it.
     */
    private fun failedGenerationReadWithBlindRollback(policy: KSafeMemoryPolicy) = runBlocking {
        val storage = FaultyStorage()
        val core = seededCore(storage, policy)

        // The batch's generation read, then the rollback's re-merge read.
        storage.failSnapshots = 2
        assertFailsWith<IOException> {
            core.putRaw("session", "phantom", mode, String.serializer())
        }
        assertEquals(0, storage.failSnapshots, "both faulted reads must have been consumed")

        assertPhantomIsGoneAndDiskWins(storage, core, policy)
    }

    @Test
    fun failedGenerationRead_dropsThePhantom_lazyPlainText() =
        failedGenerationReadWithBlindRollback(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun failedGenerationRead_dropsThePhantom_encrypted() =
        failedGenerationReadWithBlindRollback(KSafeMemoryPolicy.ENCRYPTED)

    @Test
    fun failedGenerationRead_dropsThePhantom_timedCache() =
        failedGenerationReadWithBlindRollback(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    @Test
    fun failedGenerationRead_dropsThePhantom_plainText() =
        failedGenerationReadWithBlindRollback(KSafeMemoryPolicy.PLAIN_TEXT)

    /**
     * (c) A newer write claims the key while the rollback is inside its failing read: the drop is
     * value-CAS'd, so it must take the failed write's own value and leave the newer one alone.
     */
    @Test
    fun aNewerWriteClaimingTheKeyMidRollback_isNotDropped() = runBlocking {
        val storage = FaultyStorage()
        val core = seededCore(storage, KSafeMemoryPolicy.ENCRYPTED)
        val encSlot = core.legacyEncryptedRawKey("session")

        // The newer write's own batch parks in applyBatch, so nothing repairs its optimistic
        // state before the assertions below.
        storage.parkRawKey = KeySafeMetadataManager.valueRawKey("session")
        storage.beforeSnapshotFailure = {
            core.putDirectRaw("session", "newer", mode, String.serializer())
        }
        storage.failNextApplyBatch = true

        assertFailsWith<IOException> {
            core.putRaw("session", "phantom", mode, String.serializer())
        }

        assertEquals(
            "\"newer\"", core.memoryCache[encSlot],
            "the drop must be CAS'd on the FAILED write's value: a newer writer that re-claimed " +
                "the key keeps its optimistic value",
        )
        assertTrue(
            core.isUserKeyDirty("session"),
            "and the newer writer's dirty flag must survive the failed write's release",
        )

        withTimeout(10.seconds) { storage.parkEntered.await() }
        storage.parkGate.complete(Unit)
        core.putRaw("drain", "d", KSafeWriteMode.Plain, String.serializer())

        assertEquals(
            "newer", core.getDirectRaw("session", "none", String.serializer()),
            "and the newer write commits normally",
        )
        assertEquals(
            StoredValue.Text::class,
            storage.snapshot()[KeySafeMetadataManager.valueRawKey("session")]!!::class,
            "its value reached disk",
        )
    }

    /** (d) Healthy path: the re-merge succeeds, so the previously persisted value is restored. */
    private fun failedApplyBatchWithAWorkingRollbackRead(policy: KSafeMemoryPolicy) = runBlocking {
        val storage = FaultyStorage()
        val core = seededCore(storage, policy)

        storage.applyBatchFailureBlindsNextRead = false
        storage.failNextApplyBatch = true
        assertFailsWith<IOException> {
            core.putRaw("session", "phantom", mode, String.serializer())
        }

        assertEquals(
            "old", core.getDirectRaw("session", "none", String.serializer()),
            "a rollback whose re-merge SUCCEEDS still restores the durable value, unchanged " +
                "(policy=$policy)",
        )
    }

    @Test
    fun workingRollbackRead_restoresTheDiskValue_lazyPlainText() =
        failedApplyBatchWithAWorkingRollbackRead(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun workingRollbackRead_restoresTheDiskValue_encrypted() =
        failedApplyBatchWithAWorkingRollbackRead(KSafeMemoryPolicy.ENCRYPTED)

    @Test
    fun workingRollbackRead_restoresTheDiskValue_timedCache() =
        failedApplyBatchWithAWorkingRollbackRead(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    @Test
    fun workingRollbackRead_restoresTheDiskValue_plainText() =
        failedApplyBatchWithAWorkingRollbackRead(KSafeMemoryPolicy.PLAIN_TEXT)

    /**
     * (e) A failed DELETE staged no value and no metadata, so the blind rollback's drop has
     * nothing of its own to take: the slots stay as the delete left them and disk still wins.
     */
    @Test
    fun failedDeleteWithBlindRollback_isANoOp() = runBlocking {
        val storage = FaultyStorage()
        val core = seededCore(storage, KSafeMemoryPolicy.ENCRYPTED)
        val encSlot = core.legacyEncryptedRawKey("session")

        storage.failNextApplyBatch = true
        assertFailsWith<IOException> { core.delete("session") }

        assertEquals(
            "none", core.getDirectRaw("session", "none", String.serializer()),
            "the delete rejected and its rollback read nothing, so the key reads as the default",
        )
        assertFalse(core.memoryCache.containsKey(encSlot), "the delete's own eviction stands")
        assertFalse(core.memoryCache.containsKey("session"), "for the plain slot too")
        assertNull(core.protectionMap["session"], "and the drop leaves no metadata behind")
        assertNull(core.encMetaMap["session"], "nor any envelope metadata")
        assertFalse(core.isUserKeyDirty("session"), "and the key stays mergeable")

        val epoch = core.clearEpoch.get()
        core.updateCache(storage.snapshot(), epoch)
        assertEquals(
            "old", core.getDirectRaw("session", "none", String.serializer()),
            "the value the failed delete never removed comes back on the next merge",
        )
    }

    /**
     * (f) A newer PLAIN write reclaims a failed encrypted key while the rollback is inside its
     * failing read: the metadata drop is CAS'd on the FAILED write's literals, so the plain
     * write's own protection literal (and its cleared envelope metadata) must survive.
     */
    @Test
    fun newerPlainWrite_reclaimingAFailedEncryptedKeyMidRollback_keepsItsMetadata() = runBlocking {
        val storage = FaultyStorage()
        val core = seededCore(storage, KSafeMemoryPolicy.ENCRYPTED)

        // The newer write's own batch parks in applyBatch, so nothing repairs its optimistic
        // state before the assertions below.
        storage.parkRawKey = KeySafeMetadataManager.valueRawKey("session")
        storage.beforeSnapshotFailure = {
            core.putDirectRaw("session", "v2", KSafeWriteMode.Plain, String.serializer())
        }
        storage.failNextApplyBatch = true

        assertFailsWith<IOException> {
            core.putRaw("session", "phantom", mode, String.serializer())
        }

        assertEquals(
            "v2", core.getDirectRaw("session", "none", String.serializer()),
            "the newer plain write's value survives the failed encrypted write's rollback",
        )
        assertEquals(
            KeySafeMetadataManager.protectionToLiteral(null), core.protectionMap["session"],
            "and so does its plain protection literal — the drop only takes the failed write's",
        )
        assertNull(
            core.encMetaMap["session"],
            "the plain write cleared the envelope metadata and the rollback must not restore it",
        )

        withTimeout(10.seconds) { storage.parkEntered.await() }
        storage.parkGate.complete(Unit)
        core.putRaw("drain", "d", KSafeWriteMode.Plain, String.serializer())

        assertEquals(
            "v2", core.getDirectRaw("session", "none", String.serializer()),
            "and the plain write commits normally",
        )
    }
}
