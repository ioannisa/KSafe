package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.serializer
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A `lazyLoad` instance runs no snapshot collector, so nothing but its own write path ever
 * re-reads the store's key-rotation generation. This locks in that a rotation performed by
 * a co-existing instance AFTER that instance's first write still governs its later writes —
 * otherwise they keep minting keys and metadata under a superseded generation, dropping
 * back to the unauthenticated envelope on an already-rotated store.
 */
class JvmLazyGenerationRefreshTest {

    private val keygenKey = KeySafeMetadataManager.KEYGEN_RAW_KEY
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
        lazyLoad: Boolean,
    ): KSafeCore = KSafeCore(
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

    private fun metaKey(key: String) = KeySafeMetadataManager.metadataRawKey(key)

    @Test
    fun lazyInstance_picksUpARotationThatLandedAfterItsFirstWrite() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val core = buildCore(storage, engine, lazyLoad = true)

        // First write: the store is un-rotated, so this instance settles on generation 1.
        core.putRaw("first", "a", KSafeWriteMode.Encrypted(), String.serializer())
        assertTrue("\"g\":" !in storage.text(metaKey("first"))!!)

        // A co-existing instance rotates the store to generation 2.
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":1}"""))

        core.putRaw("second", "b", KSafeWriteMode.Encrypted(), String.serializer())

        val meta = storage.text(metaKey("second"))!!
        assertTrue(
            "\"g\":2" in meta,
            "a write after another instance's rotation must commit at the store's generation, got: $meta",
        )
        assertTrue(
            "\"v\":3" in meta,
            "a generation-2 write carries the authenticated envelope, got: $meta",
        )

        // And the entry reads back through its recorded routing on a fresh instance.
        val reopened = buildCore(storage, engine, lazyLoad = true)
        assertEquals("b", reopened.getRaw("second", "", String.serializer()))
    }

    /**
     * The eager (collector-backed) construction already re-syncs on every snapshot emission;
     * this pins that the lazy fix did not have to change it.
     */
    @Test
    fun eagerInstance_alsoPicksUpTheLaterRotation() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val core = buildCore(storage, engine, lazyLoad = false)

        core.putRaw("first", "a", KSafeWriteMode.Encrypted(), String.serializer())
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":1}"""))
        // The collector is what carries the rotation here; wait for it rather than racing it.
        withTimeout(10.seconds) { while (core.currentKeyGeneration.get() < 2) delay(1) }
        core.putRaw("second", "b", KSafeWriteMode.Encrypted(), String.serializer())

        assertTrue("\"g\":2" in storage.text(metaKey("second"))!!)
    }
}
