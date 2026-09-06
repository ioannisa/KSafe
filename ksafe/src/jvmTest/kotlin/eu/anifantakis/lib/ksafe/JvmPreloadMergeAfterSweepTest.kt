package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.serializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: a cold-cache preload whose snapshot predates the startup orphan sweep is not merged
 * after it. Landing last, it would put the swept entry's metadata back into the cache until the
 * store's next write; a preload that loses that race re-reads the store, since dropping it would
 * serve a default for a key the store holds. Under lazy load the sweep drops the metadata itself.
 */
class JvmPreloadMergeAfterSweepTest {

    private val cores = mutableListOf<KSafeCore>()

    @AfterTest
    fun tearDown() {
        cores.forEach { it.cancel() }
        cores.clear()
    }

    private val valueKey = KeySafeMetadataManager.valueRawKey("canary")
    private val metaKey = KeySafeMetadataManager.metadataRawKey("canary")

    /**
     * In-memory storage that hands back the preload's first snapshot() only when the test releases
     * it, while the collector's flow starts after that read begins. [readAfterRelease] takes that
     * snapshot after the release, making it the fresher one; [collectOnceOnly] parks the collector
     * after its first merge; [merged] is the last snapshot the collector finished merging.
     */
    private class StaleReadStorage(
        private val readAfterRelease: Boolean = false,
        private val collectOnceOnly: Boolean = false,
    ) : KSafePlatformStorage {
        private val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())
        val preloadRead = CompletableDeferred<Unit>()
        val releasePreload = CompletableDeferred<Unit>()
        val merged = MutableStateFlow<Map<String, StoredValue>?>(null)

        override suspend fun snapshot(): Map<String, StoredValue> {
            if (!preloadRead.complete(Unit)) return state.value
            val early = if (readAfterRelease) null else state.value
            releasePreload.await()
            return early ?: state.value
        }

        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = flow {
            preloadRead.await()
            state.collect { snapshot ->
                emit(snapshot)
                merged.value = snapshot
                if (collectOnceOnly) awaitCancellation()
            }
        }

        override suspend fun applyBatch(ops: List<StorageOp>) {
            state.update { current ->
                val next = current.toMutableMap()
                for (op in ops) when (op) {
                    is StorageOp.Put -> next[op.rawKey] = op.value
                    is StorageOp.Delete -> next.remove(op.rawKey)
                }
                next
            }
        }

        override suspend fun clear() { state.value = emptyMap() }

        fun seed(vararg pairs: Pair<String, StoredValue>) { state.update { it + pairs } }
        fun holds(rawKey: String): Boolean = state.value.containsKey(rawKey)
    }

    /** A genuine orphan: HARDWARE_ISOLATED ciphertext whose per-entry key was never minted. */
    @OptIn(ExperimentalEncodingApi::class)
    private fun seededStorage(): StaleReadStorage = StaleReadStorage().apply {
        seed(
            valueKey to StoredValue.Text(Base64.encode("ciphertext-under-a-missing-key".encodeToByteArray())),
            metaKey to StoredValue.Text("""{"v":2,"p":"HARDWARE_ISOLATED"}"""),
        )
    }

    private fun buildCore(storage: KSafePlatformStorage, lazyLoad: Boolean): KSafeCore = KSafeCore(
        storage = storage,
        engineProvider = { StatefulFakeEncryption() },
        config = KSafeConfig(),
        memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        plaintextCacheTtl = 5.seconds,
        resolveKeyStorage = { _, _, _ -> KSafeKeyStorage.SOFTWARE },
        resolveKeyLevel = { _, _, _ -> KSafeProtectionLevel.SOFTWARE },
        lazyLoad = lazyLoad,
        keyAlias = { "p.$it" },
        masterAlias = { req -> if (req) "master_locked" else "master" },
    ).also { cores.add(it) }

    private suspend fun preloadReadBeforeTheSweepLandsAfterIt(
        storage: StaleReadStorage,
        core: KSafeCore,
        preload: suspend () -> Unit,
    ) = coroutineScope {
        // Its snapshot is read now, before the collector has merged anything.
        val staleMerge = async(Dispatchers.IO) { preload() }
        withTimeout(10.seconds) { storage.preloadRead.await() }
        // The collector has swept the orphan and finished merging the post-sweep state.
        withTimeout(10.seconds) { storage.merged.first { it != null && valueKey !in it } }
        storage.releasePreload.complete(Unit)
        withTimeout(10.seconds) { staleMerge.await() }

        assertFalse(storage.holds(valueKey), "sanity: the sweep deleted the orphan from the store")
        assertNull(
            core.getKeyInfo("canary"),
            "a preload snapshot read before the startup sweep was merged after it and put the " +
                "swept orphan back into the cache",
        )
    }

    @Test
    fun aSuspendReadsPreloadReadBeforeTheSweep_doesNotResurrectTheSweptOrphan() = runBlocking {
        val storage = seededStorage()
        val core = buildCore(storage, lazyLoad = false)
        preloadReadBeforeTheSweepLandsAfterIt(storage, core) {
            core.getRaw("canary", "", String.serializer())
        }
    }

    @Test
    fun aBlockingReadsPreloadReadBeforeTheSweep_doesNotResurrectTheSweptOrphan() = runBlocking {
        val storage = seededStorage()
        val core = buildCore(storage, lazyLoad = false)
        preloadReadBeforeTheSweepLandsAfterIt(storage, core) {
            core.getKeyInfo("canary")
        }
    }

    /** The other half of the same race: the dropped preload's default would let getOrCreateSecret,
     *  deciding purely from the cache, mint a new secret over a live one. */
    @Test
    fun aPreloadSnapshotFresherThanTheLandedMerge_isNotDropped() = runBlocking {
        val storage = StaleReadStorage(readAfterRelease = true, collectOnceOnly = true)
        val core = buildCore(storage, lazyLoad = false)
        coroutineScope {
            val preload = async(Dispatchers.IO) { core.getRaw("fresh", "default", String.serializer()) }
            withTimeout(10.seconds) { storage.preloadRead.await() }
            // The collector merged the empty store, so the cache counts as initialised.
            withTimeout(10.seconds) { storage.merged.first { it != null } }
            // Committed after that merge, and the collector is done: only the preload can see it.
            storage.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("fresh"), StoredValue.Text("v")),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("fresh"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(null, accessPolicy = null)),
                    ),
                ),
            )
            storage.releasePreload.complete(Unit)

            assertEquals(
                "v",
                withTimeout(10.seconds) { preload.await() },
                "a preload snapshot fresher than the merge that landed while it waited was dropped, " +
                    "so the cold read served a default for a key the store holds",
            )
        }
    }

    @Test
    fun underLazyLoad_theSweepItselfDropsTheOrphansMetadata() = runBlocking {
        val storage = seededStorage()
        val core = buildCore(storage, lazyLoad = true)
        // The first access preloads the cache and triggers the sweep; nothing merges after it.
        storage.releasePreload.complete(Unit)
        core.getKeyInfo("canary")
        withTimeout(10.seconds) { while (storage.holds(valueKey)) delay(10) }

        assertNull(
            core.getKeyInfo("canary"),
            "with no collector to merge the post-sweep state, the sweep must drop the orphan's " +
                "metadata itself or getKeyInfo reports an entry the store no longer holds",
        )
    }
}
