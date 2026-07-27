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
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.serializer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in the store key-generation authority invariants:
 * - the PERSISTED generation governs a cold/lazy instance's first write (no silent
 *   regression of a rotated store to generation-1 / v2 envelopes),
 * - a stale rotation can never roll the persisted generation record backwards,
 * - a clearAll landing inside an in-flight rotation fences the pass — post-clear writes
 *   are never stamped with the stale target generation,
 * - a rotation entry superseded before its commit does not strand the freshly minted
 *   target-generation key in the vault,
 * - a fabricated huge generation record is clamped (no unbounded sweep loops, no
 *   increment overflow) and rotation refuses past the bound,
 * - an envelope version from the future fails closed: unreadable but PRESERVED.
 */
class JvmGenerationAuthorityTest {

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
        val current: Map<String, StoredValue> get() = state.value
        fun text(rawKey: String): String? = (state.value[rawKey] as? StoredValue.Text)?.value
    }

    /**
     * [StatefulFakeEncryption] whose SUSPEND decrypt pauses AFTER a successful decrypt at a
     * test-armed gate — the exact window where a rotation already holds an entry's decrypted
     * payload but has not yet enqueued its re-encrypt commit. The gate stays armed once set:
     * the lazy startup cleanup's orphan probe also decrypts on a background scope, and only
     * holding EVERY suspend decrypt at the gate guarantees the rotation's re-encrypt op is
     * enqueued after whatever the test interleaves before releasing.
     */
    private class GatedStatefulEncryption : StatefulFakeEncryption() {
        val decryptEntered = CompletableDeferred<Unit>()
        val decryptGate = CompletableDeferred<Unit>()
        @Volatile var gateArmed = false

        override suspend fun decryptSuspend(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            val plain = decrypt(identifier, data, requireUnlockedDevice, aad)
            if (gateArmed) {
                decryptEntered.complete(Unit)
                decryptGate.await()
            }
            return plain
        }
    }

    private fun buildCore(
        storage: KSafePlatformStorage,
        engine: StatefulFakeEncryption,
        lazyLoad: Boolean = true,
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
    private fun valueKey(key: String) = KeySafeMetadataManager.valueRawKey(key)

    // ---- persisted generation governs a cold instance's first write ----------------------

    @Test
    fun coldLazyInstanceImmediateWrite_staysAtTheRotatedGeneration() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":1}"""))

        // Lazy instance, no cache merge before the write: the local generation still holds
        // the constructor default when the put captures it.
        val core = buildCore(storage, engine)
        core.putRaw("token", "secret", KSafeWriteMode.Encrypted(), String.serializer())

        val meta = storage.text(metaKey("token"))!!
        assertTrue("\"g\":2" in meta, "the write must commit at the STORE's generation, got: $meta")
        assertTrue("\"v\":3" in meta, "a generation-2 write carries the authenticated v3 envelope, got: $meta")

        // And it round-trips on a fresh instance through the recorded routing.
        val reopened = buildCore(storage, engine)
        assertEquals("secret", reopened.getRaw("token", "", String.serializer()))
    }

    // ---- a stale rotation never regresses the persisted record ---------------------------

    @Test
    fun staleRotation_cannotRollThePersistedGenerationBack() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val core = buildCore(storage, engine)

        core.putRaw("k", "v", KSafeWriteMode.Encrypted(), String.serializer())
        assertEquals(2, core.rotateKeys().keyGeneration)
        assertEquals(3, core.rotateKeys().keyGeneration)
        val persistedAtG3 = storage.text(keygenKey)!!
        assertTrue("\"g\":3" in persistedAtG3)

        // Simulate a stale sibling's view of the store: local generation back at 1 while the
        // persisted record says 3. Its rotation targets generation 2 — BELOW the authority.
        core.currentKeyGeneration.set(1)
        val stale = core.rotateKeys()

        assertEquals(
            persistedAtG3, storage.text(keygenKey),
            "a stale rotation must never overwrite a newer persisted generation record",
        )
        assertEquals(0, stale.rotated, "no entry may be re-stamped with a stale target generation")
        assertEquals(3, core.currentKeyGeneration.get(), "the pass reconciles the local view up to the authority")

        // The store still works and the next rotation proceeds from the true generation.
        assertEquals("v", core.getRaw("k", "", String.serializer()))
        assertEquals(4, core.rotateKeys().keyGeneration)
        assertEquals("v", core.getRaw("k", "", String.serializer()))
    }

    // ---- clearAll fences an in-flight rotation -------------------------------------------

    @Test
    fun clearAllDuringRotation_fencesTheStaleTarget_andCleansTheMintedKey() = runBlocking {
        val storage = InMemoryStorage()
        val engine = GatedStatefulEncryption()
        val core = buildCore(storage, engine)

        core.putRaw(
            "hw", "isolated",
            KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
            String.serializer(),
        )

        engine.gateArmed = true
        val rotation = async(Dispatchers.Default) { core.rotateKeys() }
        withTimeout(10.seconds) { engine.decryptEntered.await() }

        // The rotation is paused between its generation bump and the entry's re-encrypt
        // commit — exactly the window clearAll must fence.
        core.clearAll()
        core.putRaw("fresh", "post-clear", KSafeWriteMode.Encrypted(), String.serializer())
        engine.decryptGate.complete(Unit)
        val result = withTimeout(10.seconds) { rotation.await() }

        assertEquals(0, result.rotated, "nothing may commit against a cleared store")
        assertEquals(1, result.skipped, "the fenced entry is reported skipped, not failed")
        val freshMeta = storage.text(metaKey("fresh"))!!
        assertFalse(
            "\"g\":" in freshMeta,
            "a post-clear write must stay at the store's reset generation, got: $freshMeta",
        )
        // The pass had already minted the target-generation key for the fenced entry; a
        // skipped commit must reclaim it instead of stranding it in the vault forever.
        val targetAlias = KSafeCore.perEntryAliasWithGeneration("p.hw", 2, null, "hw")
        assertFalse(
            targetAlias in engine.liveAliases(),
            "the fenced rotation's freshly minted key must be reclaimed",
        )

        // The store stays healthy: the next rotation proceeds normally.
        val next = core.rotateKeys()
        assertEquals(2, next.keyGeneration)
        assertEquals(1, next.rotated)
        assertEquals("post-clear", core.getRaw("fresh", "", String.serializer()))
    }

    // ---- a superseded rotation entry reclaims its minted target key ----------------------

    @Test
    fun deleteDuringRotation_reclaimsTheFreshlyMintedTargetKey() = runBlocking {
        val storage = InMemoryStorage()
        val engine = GatedStatefulEncryption()
        val core = buildCore(storage, engine)

        core.putRaw(
            "hw", "isolated",
            KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
            String.serializer(),
        )

        engine.gateArmed = true
        val rotation = async(Dispatchers.Default) { core.rotateKeys() }
        withTimeout(10.seconds) { engine.decryptEntered.await() }

        // The entry is deleted in a separate batch while the rotation still holds its
        // decrypted copy; the rotation's later commit CAS must skip — and must not leave
        // the target-generation key it minted during its encrypt phase.
        core.delete("hw")
        engine.decryptGate.complete(Unit)
        val result = withTimeout(10.seconds) { rotation.await() }

        assertEquals(0, result.rotated)
        val targetAlias = KSafeCore.perEntryAliasWithGeneration("p.hw", 2, null, "hw")
        assertFalse(
            targetAlias in engine.liveAliases(),
            "a CAS-skipped rotation must reclaim the virgin key it minted for the target generation",
        )
        assertEquals(null, storage.current[valueKey("hw")], "the delete wins")
    }

    // ---- fabricated huge generation records ----------------------------------------------

    @Test
    fun fabricatedHugeGeneration_isClamped_andRotationRefusesPastTheBound() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        storage.seed(keygenKey to StoredValue.Text("""{"g":2147483647,"ts":1}"""))
        val core = buildCore(storage, engine)

        // Rotation refuses (no wrap past the parser bound), with the store intact.
        assertFailsWith<IllegalStateException> { core.rotateKeys() }
        assertEquals(KeySafeMetadataManager.MAX_KEY_GENERATION, core.currentKeyGeneration.get())

        // Writes and the full wipe complete promptly — the sweep loops are bounded.
        core.putRaw("k", "v", KSafeWriteMode.Encrypted(), String.serializer())
        core.clearAll()
        assertEquals(1, core.currentKeyGeneration.get(), "a wiped store restarts at the base generation")
        assertEquals(2, core.rotateKeys().keyGeneration, "rotation works again after the reset")
    }

    // ---- future envelope versions fail closed --------------------------------------------

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun futureEnvelopeVersion_failsClosed_entryPreservedNotSweptNotRotated() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val junk = Base64.encode("ciphertext-from-a-newer-ksafe".encodeToByteArray())
        storage.seed(
            // An entry stamped with an envelope version this build does not know.
            valueKey("future") to StoredValue.Text(junk),
            metaKey("future") to StoredValue.Text("""{"v":4,"p":"DEFAULT"}"""),
            // A genuine orphan — per-entry alias, so the master the prewarm mints can't
            // shadow the missing key — proves the sweep RAN before the assertions below.
            valueKey("orphan") to StoredValue.Text(junk),
            metaKey("orphan") to StoredValue.Text("""{"v":2,"p":"HARDWARE_ISOLATED"}"""),
        )

        val core = buildCore(storage, engine, lazyLoad = false)
        withTimeout(10.seconds) {
            while (storage.current.containsKey(valueKey("orphan"))) delay(20)
        }

        assertTrue(
            storage.current.containsKey(valueKey("future")),
            "an unknown-version entry must be PRESERVED for the newer KSafe that wrote it",
        )
        assertEquals(
            "fallback", core.getRaw("future", "fallback", String.serializer()),
            "an unknown-version entry must fail closed to the default, never decrypt as v3",
        )

        // Rotation cannot re-encrypt what it cannot understand: counted failed, value intact.
        val result = core.rotateKeys()
        assertEquals(0, result.rotated)
        assertEquals(1, result.failed)
        assertEquals(junk, storage.text(valueKey("future")), "the ciphertext must stay untouched")
    }
}
