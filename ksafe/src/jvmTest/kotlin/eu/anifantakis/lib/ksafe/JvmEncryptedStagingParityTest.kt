package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.serializer
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: the fire-and-forget encrypted write (`putDirect`) and the suspending one (`put`) stage
 * IDENTICAL optimistic state and enqueue an identical op. The two bodies were copies that had
 * drifted — the suspending one published the routing literal before the value, so a concurrent
 * read could be routed to a still-empty encrypted slot — and now share one staging step.
 */
class JvmEncryptedStagingParityTest {

    /** In-memory storage that parks the consumer inside the batch touching [parkRawKey]. */
    private class ParkingStorage : KSafePlatformStorage {
        private val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())

        @Volatile private var parkRawKey: String? = null
        val parked = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()

        fun parkBatchTouching(rawKey: String) { parkRawKey = rawKey }

        override suspend fun snapshot(): Map<String, StoredValue> = state.value
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = state

        override suspend fun applyBatch(ops: List<StorageOp>) {
            val park = parkRawKey
            if (park != null && ops.any { it.rawKey == park }) {
                parkRawKey = null
                parked.complete(Unit)
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
    }

    /** Everything a staged encrypted write leaves behind, plus the op it enqueues. */
    private data class Staged(
        val encSlot: Any?,
        val plainSlot: Any?,
        val protection: String?,
        val encMeta: KSafeCore.EncMeta?,
        val encDirty: Boolean,
        val plainDirty: Boolean,
        val sideCache: String?,
        val plainSideCache: String?,
        val anyEncryptedFlag: Boolean,
        val opUserKey: String,
        val opRawCacheKey: String,
        val opJson: String,
        val opProtection: KSafeProtection,
        val opRequireUnlocked: Boolean,
        val opGeneration: Int,
        val opSuperseded: List<String>,
        val opOwnsLatestToken: Boolean,
    )

    private enum class Seed { NONE, PLAIN, PER_ENTRY_ALIAS }

    private val cores = mutableListOf<KSafeCore>()

    @AfterTest
    fun tearDown() {
        cores.forEach { it.cancel() }
        cores.clear()
    }

    private fun buildCore(storage: KSafePlatformStorage, policy: KSafeMemoryPolicy): KSafeCore =
        KSafeCore(
            storage = storage,
            engineProvider = { StatefulFakeEncryption() },
            config = KSafeConfig(),
            memoryPolicy = policy,
            plaintextCacheTtl = 5.seconds,
            resolveKeyStorage = { _, _, _ -> KSafeKeyStorage.SOFTWARE },
            resolveKeyLevel = { _, _, _ -> KSafeProtectionLevel.SOFTWARE },
            lazyLoad = true, // no collector, so nothing repairs or re-merges behind the snapshot
            keyAlias = { "p.$it" },
            masterAlias = { req -> if (req) "master_locked" else "master" },
        ).also { cores.add(it) }

    /** Parks the consumer so a staged write stays observable in the maps and in the channel. */
    private suspend fun parkConsumer(core: KSafeCore, storage: ParkingStorage) {
        storage.parkBatchTouching(KeySafeMetadataManager.valueRawKey("barrier"))
        core.putDirectRaw("barrier", 1, KSafeWriteMode.Plain, Int.serializer())
        withTimeout(10.seconds) { storage.parked.await() }
    }

    /** Brings a fresh core to the pre-write state [seed] describes. */
    private suspend fun applySeed(core: KSafeCore, key: String, seed: Seed) {
        when (seed) {
            Seed.NONE -> Unit
            Seed.PLAIN -> core.putRaw(key, "old-plain", KSafeWriteMode.Plain, String.serializer())
            Seed.PER_ENTRY_ALIAS -> core.putRaw(
                key,
                "old-secret",
                KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
                String.serializer(),
            )
        }
        // FIFO drain: once this returns, the seed's post-commit repair has run.
        core.putRaw("drain", "d", KSafeWriteMode.Plain, String.serializer())
    }

    private suspend fun takeOp(core: KSafeCore): KSafeCore.PendingWrite.Encrypted =
        withTimeout(10.seconds) {
            var op = core.writeChannel.tryReceive().getOrNull()
            while (op == null) {
                delay(1)
                op = core.writeChannel.tryReceive().getOrNull()
            }
            op as KSafeCore.PendingWrite.Encrypted
        }

    private fun snapshotStaged(
        core: KSafeCore,
        key: String,
        op: KSafeCore.PendingWrite.Encrypted,
    ): Staged {
        val enc = core.legacyEncryptedRawKey(key)
        return Staged(
            encSlot = core.memoryCache[enc],
            plainSlot = core.memoryCache[key],
            protection = core.protectionMap[key],
            encMeta = core.encMetaMap[key],
            encDirty = core.dirtyKeys.contains(enc),
            plainDirty = core.dirtyKeys.contains(key),
            sideCache = core.plaintextCache[enc]?.value,
            plainSideCache = core.plaintextCache[key]?.value,
            anyEncryptedFlag = core.hasAnyEncryptedKey.get(),
            opUserKey = op.userKey,
            opRawCacheKey = op.rawCacheKey,
            opJson = op.jsonString,
            opProtection = op.protection,
            opRequireUnlocked = op.requireUnlockedDevice,
            opGeneration = op.keyGeneration,
            opSuperseded = op.supersededAliases,
            opOwnsLatestToken = core.writeOwners[key] === op.writeToken,
        )
    }

    private fun parity(policy: KSafeMemoryPolicy, requireUnlocked: Boolean, seed: Seed) = runBlocking {
        val key = "session"
        val value = "s3cret"
        val mode = KSafeWriteMode.Encrypted(requireUnlockedDevice = requireUnlocked)
        val case = "policy=$policy requireUnlocked=$requireUnlocked seed=$seed"

        val directStorage = ParkingStorage()
        val directCore = buildCore(directStorage, policy)
        applySeed(directCore, key, seed)
        parkConsumer(directCore, directStorage)
        directCore.putDirectRaw(key, value, mode, String.serializer())
        val directOp = takeOp(directCore)
        val direct = snapshotStaged(directCore, key, directOp)

        val suspendStorage = ParkingStorage()
        val suspendCore = buildCore(suspendStorage, policy)
        applySeed(suspendCore, key, seed)
        parkConsumer(suspendCore, suspendStorage)
        // Its op is taken from under the parked consumer, so the awaited commit never arrives.
        val writer: Job = launch(Dispatchers.Default) { suspendCore.putRaw(key, value, mode, String.serializer()) }
        val suspendOp = takeOp(suspendCore)
        val suspended = snapshotStaged(suspendCore, key, suspendOp)
        writer.cancel()

        assertEquals(direct, suspended, "the two encrypted write paths must stage the same state ($case)")

        // The order the shared staging step guarantees, at the only boundary a caller can observe.
        assertNotNull(direct.protection, "routing metadata must be published ($case)")
        assertEquals(value.jsonQuoted(), direct.encSlot, "the encrypted slot must hold the value ($case)")
        assertTrue(direct.encDirty, "the in-flight write must be flagged dirty ($case)")
        assertTrue(direct.opOwnsLatestToken, "the op must own the key's latest write token ($case)")
        assertNull(direct.plainSlot, "a superseded plain slot must not survive ($case)")

        assertNull(directOp.completion, "putDirect must not await a commit ($case)")
        assertNotNull(suspendOp.completion, "the suspending put must await its commit ($case)")
    }

    private fun String.jsonQuoted() = "\"$this\""

    private fun parityAcrossCases(policy: KSafeMemoryPolicy) {
        for (requireUnlocked in listOf(false, true)) {
            for (seed in Seed.entries) parity(policy, requireUnlocked, seed)
        }
    }

    @Test
    fun stagingIsIdenticalOnBothWritePaths_encrypted() =
        parityAcrossCases(KSafeMemoryPolicy.ENCRYPTED)

    @Test
    fun stagingIsIdenticalOnBothWritePaths_timedCache() =
        parityAcrossCases(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)

    @Test
    fun stagingIsIdenticalOnBothWritePaths_lazyPlainText() =
        parityAcrossCases(KSafeMemoryPolicy.LAZY_PLAIN_TEXT)

    @Test
    fun stagingIsIdenticalOnBothWritePaths_plainText() =
        parityAcrossCases(KSafeMemoryPolicy.PLAIN_TEXT)
}
