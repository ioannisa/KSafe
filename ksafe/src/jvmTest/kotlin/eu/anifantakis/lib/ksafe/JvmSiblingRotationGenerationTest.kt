package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.SiblingRegistry
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.serializer
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: a rotation on one instance leaves every other instance's next write committing at the
 * store's generation. A sibling whose collector has not seen the rotation adopts the new generation
 * into its routing metadata, so a write it staged beforehand would otherwise persist a record one
 * generation below what that instance believes it wrote.
 */
class JvmSiblingRotationGenerationTest {

    private val cores = mutableListOf<KSafeCore>()

    @AfterTest
    fun tearDown() {
        cores.forEach { it.cancel() }
        cores.clear()
    }

    /** One physical store behind two facades; [observable] false emits once, then never again. */
    private class SharedStorage(
        private val state: MutableStateFlow<Map<String, StoredValue>>,
        private val observable: Boolean,
    ) : KSafePlatformStorage {
        override suspend fun snapshot(): Map<String, StoredValue> = state.value
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> =
            if (observable) state else flow { emit(state.value); awaitCancellation() }
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

    /** Parks the next encrypt so the rotation batch holds the shared commit mutex open. */
    private class GatingEngine(private val delegate: KSafeEncryption) : KSafeEncryption by delegate {
        @Volatile var armed = false
        val reached = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()

        override suspend fun encryptSuspend(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            if (armed) {
                armed = false
                reached.complete(Unit)
                release.await()
            }
            return delegate.encryptSuspend(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)
        }
    }

    private fun buildCore(
        storage: KSafePlatformStorage,
        engine: KSafeEncryption,
        mutex: Mutex,
        registry: SiblingRegistry,
    ): KSafeCore = KSafeCore(
        storage = storage,
        engineProvider = { engine },
        config = KSafeConfig(),
        commitMutex = mutex,
        memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
        plaintextCacheTtl = 5.seconds,
        resolveKeyStorage = { _, _, _ -> KSafeKeyStorage.SOFTWARE },
        resolveKeyLevel = { _, _, _ -> KSafeProtectionLevel.SOFTWARE },
        lazyLoad = false,
        keyAlias = { "p.$it" },
        masterAlias = { req -> if (req) "master_locked" else "master" },
    ).also { cores.add(it); registry.register(it); it.attachSiblings(registry) }

    @Test
    fun aWriteStagedBeforeASiblingsRotation_commitsAtTheGenerationItsMetadataRecords() = runBlocking {
        val engine = StatefulFakeEncryption()
        val gating = GatingEngine(engine)
        val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())
        val mutex = Mutex()
        val registry = SiblingRegistry()

        val a = buildCore(SharedStorage(state, observable = true), gating, mutex, registry)
        a.putRaw("token", "v", KSafeWriteMode.Encrypted(), String.serializer())

        // b merges once at construction and then never again: it cannot see the rotation's record.
        val b = buildCore(SharedStorage(state, observable = false), engine, mutex, registry)
        assertEquals("v", b.getRaw("token", "", String.serializer()), "precondition: the sibling holds the entry")
        assertEquals(1, b.currentKeyGeneration.get(), "precondition: the sibling is at the base generation")

        gating.armed = true
        val rotation = async(Dispatchers.IO) { a.rotateKeys() }
        // The rotation batch is parked mid-encrypt, holding the store's commit mutex.
        withTimeout(10.seconds) { gating.reached.await() }

        // Staged now, so its routing metadata records generation 1; it commits after the rotation.
        b.putDirectRaw("token", "v", KSafeWriteMode.Encrypted(), String.serializer())

        gating.release.complete(Unit)
        withTimeout(10.seconds) { rotation.await() }
        b.putRaw("drain", "d", KSafeWriteMode.Plain, String.serializer()) // FIFO: the staged write settled

        val recorded = KeySafeMetadataManager.parseKeyGeneration(
            (state.value[KeySafeMetadataManager.metadataRawKey("token")] as? StoredValue.Text)?.value,
        )
        assertEquals(
            b.encMetaMap["token"]?.keyGeneration, recorded,
            "the sibling's persisted record must carry the generation its own routing metadata names",
        )
        assertEquals(2, recorded, "and that is the rotated store's generation")
    }
}
