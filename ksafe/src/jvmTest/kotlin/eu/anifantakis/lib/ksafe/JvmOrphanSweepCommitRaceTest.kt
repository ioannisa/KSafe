package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.serializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: the startup orphan-ciphertext sweep's final check + delete are atomic with respect
 * to sibling same-file instances — both run under the shared per-store commit mutex. A sibling's
 * dirtyKeys are invisible to the sweeping instance, so without the mutex a sibling could commit
 * a fresh value for the swept key between the sweep's fresh-snapshot check and its delete batch,
 * and the delete would silently erase the acknowledged write and its metadata.
 */
class JvmOrphanSweepCommitRaceTest {

    private val cores = mutableListOf<KSafeCore>()

    @AfterTest
    fun tearDown() {
        cores.forEach { it.cancel() }
        cores.clear()
    }

    /**
     * In-memory storage whose applyBatch parks the orphan sweep's delete batch (an all-delete
     * batch touching [gateValueRawKey]) at a test-controlled gate — the exact point between the
     * sweep's fresh-snapshot check and the deletion landing on disk.
     */
    private class GatedStorage(private val gateValueRawKey: String) : KSafePlatformStorage {
        private val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())
        val deleteEntered = CompletableDeferred<Unit>()
        val deleteGate = CompletableDeferred<Unit>()
        @Volatile private var gated = false

        override suspend fun snapshot(): Map<String, StoredValue> = state.value
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = state

        override suspend fun applyBatch(ops: List<StorageOp>) {
            val isOrphanDelete = ops.isNotEmpty() &&
                ops.all { it is StorageOp.Delete } &&
                ops.any { (it as StorageOp.Delete).rawKey == gateValueRawKey }
            if (isOrphanDelete && !gated) {
                gated = true
                deleteEntered.complete(Unit)
                deleteGate.await()
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

        fun seed(vararg pairs: Pair<String, StoredValue>) { state.update { it + pairs } }
        fun text(rawKey: String): String? = (state.value[rawKey] as? StoredValue.Text)?.value
    }

    private fun buildCore(
        storage: KSafePlatformStorage,
        engine: StatefulFakeEncryption,
        commitMutex: Mutex,
        lazyLoad: Boolean,
    ): KSafeCore = KSafeCore(
        commitMutex = commitMutex,
        storage = storage,
        engineProvider = { engine },
        config = KSafeConfig(),
        memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        plaintextCacheTtl = 5.seconds,
        resolveKeyStorage = { _, _, _ -> KSafeKeyStorage.SOFTWARE },
        resolveKeyLevel = { _, _, _ -> KSafeProtectionLevel.SOFTWARE },
        lazyLoad = lazyLoad,
        keyAlias = { "p.$it" },
        masterAlias = { req -> if (req) "master_locked" else "master" },
    ).also { cores.add(it) }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun siblingCommitDuringTheSweepsDeleteWindow_cannotBeErased() = runBlocking {
        val valueKey = KeySafeMetadataManager.valueRawKey("token")
        val metaKey = KeySafeMetadataManager.metadataRawKey("token")
        val storage = GatedStorage(valueKey)
        val engine = StatefulFakeEncryption()
        val sharedMutex = Mutex()

        // A genuine orphan: HARDWARE_ISOLATED ciphertext whose per-entry alias was never minted.
        storage.seed(
            valueKey to StoredValue.Text(Base64.encode("junk-under-a-missing-key".encodeToByteArray())),
            metaKey to StoredValue.Text("""{"v":2,"p":"HARDWARE_ISOLATED"}"""),
        )

        // Sweeper instance: its startup sweep classifies "token" as orphan and parks inside the
        // delete batch — after its fresh-snapshot check, still holding the shared commit mutex.
        buildCore(storage, engine, sharedMutex, lazyLoad = false)
        withTimeout(10.seconds) { storage.deleteEntered.await() }

        // Sibling instance on the same physical store commits a replacement for the same key.
        // Its dirtyKeys are invisible to the sweeper — only the shared mutex protects it.
        val sibling = buildCore(storage, engine, sharedMutex, lazyLoad = true)
        val siblingPut = async(Dispatchers.Default) {
            sibling.putRaw("token", "replacement", KSafeWriteMode.Encrypted(), String.serializer())
        }

        delay(300)
        assertFalse(
            siblingPut.isCompleted,
            "the sibling's commit must serialize AFTER the sweep's check+delete " +
                "(without the shared mutex it would land inside the delete window and be erased)",
        )

        storage.deleteGate.complete(Unit)
        withTimeout(10.seconds) { siblingPut.await() }

        assertNotNull(
            storage.text(valueKey),
            "the sibling's acknowledged write must survive the sweep's delete",
        )
        assertNotNull(storage.text(metaKey), "the replacement's metadata must survive too")
        assertEquals(
            "replacement",
            sibling.getRaw("token", "", String.serializer()),
            "the replacement value must be readable after the sweep",
        )
        assertTrue(
            engine.encryptedKeys.isNotEmpty(),
            "sanity: the sibling's write went through the engine",
        )
    }
}
