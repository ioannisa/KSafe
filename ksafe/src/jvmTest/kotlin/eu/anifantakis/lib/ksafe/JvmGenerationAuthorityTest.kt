package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.coreparts.processWrites
import kotlinx.coroutines.CancellationException
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
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
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
 * - a crash-persisted rotation marker is resumed automatically at the SAME generation
 *   by the next instance, even under the default `Never` policy,
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
        @Volatile var inProgressKeygenWrites = 0

        override suspend fun snapshot(): Map<String, StoredValue> = state.value
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = state
        override suspend fun applyBatch(ops: List<StorageOp>) {
            for (op in ops) {
                if (
                    op is StorageOp.Put &&
                    op.rawKey == KeySafeMetadataManager.KEYGEN_RAW_KEY &&
                    KeySafeMetadataManager.parseKeyRotationInProgress(
                        (op.value as? StoredValue.Text)?.value
                    )
                ) {
                    inProgressKeygenWrites++
                }
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

    /** Models the real engines' retryable require-unlocked failure. */
    private class LockableStatefulEncryption : StatefulFakeEncryption() {
        @Volatile var locked = false
        @Volatile var lockedDecryptAttempts = 0

        override suspend fun decryptSuspend(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            if (locked && requireUnlockedDevice == true) {
                lockedDecryptAttempts++
                throw IllegalStateException("device is locked")
            }
            return super.decryptSuspend(identifier, data, requireUnlockedDevice, aad)
        }
    }

    private fun buildCore(
        storage: KSafePlatformStorage,
        engine: StatefulFakeEncryption,
        lazyLoad: Boolean = true,
        config: KSafeConfig = KSafeConfig(),
    ): KSafeCore = KSafeCore(
        storage = storage,
        engineProvider = { engine },
        config = config,
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

    // ---- interrupted rotation resumes automatically on the next instance ----------------

    @Test
    fun first31Launch_adopts30RotationAsCompleted_withoutTouchingEntriesOrRunningMaxAge() =
        runBlocking {
            val storage = InMemoryStorage()
            val engine = StatefulFakeEncryption()
            val creator = buildCore(storage, engine)
            creator.startupCleanupDone.set(true)
            creator.putRaw("old", "old-value", KSafeWriteMode.Encrypted(), String.serializer())

            // Exact mixed-generation state that 3.0.0 could leave after a crash: the store
            // bumped to g2, a later write already used g2, but one older entry remains on g1.
            // 3.0.0 had no lifecycle field, so 3.1.0 MUST NOT guess whether this pass had
            // returned normally or died; absence is conservatively adopted as completed.
            storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":1}"""))
            creator.putRaw("new", "new-value", KSafeWriteMode.Encrypted(), String.serializer())
            val oldValueBefore = storage.text(valueKey("old"))
            val oldMetaBefore = storage.text(metaKey("old"))
            val newValueBefore = storage.text(valueKey("new"))
            val newMetaBefore = storage.text(metaKey("new"))
            assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(oldMetaBefore))
            assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(newMetaBefore))
            creator.cancel()

            val policy = KSafeConfig(
                keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(1.milliseconds)
            )
            val upgraded = buildCore(storage, engine, lazyLoad = false, config = policy)
            withTimeout(10.seconds) {
                while (KeySafeMetadataManager.parseKeyRotationLifecycle(storage.text(keygenKey)) != 0) {
                    delay(20)
                }
            }
            // Give the background maintenance coroutine enough time to expose an accidental
            // same-launch MaxAge fall-through. Adoption must be the ONLY action this launch.
            delay(200)

            assertEquals("""{"g":2,"ts":1,"r":0}""", storage.text(keygenKey))
            assertEquals(oldValueBefore, storage.text(valueKey("old")))
            assertEquals(oldMetaBefore, storage.text(metaKey("old")))
            assertEquals(newValueBefore, storage.text(valueKey("new")))
            assertEquals(newMetaBefore, storage.text(metaKey("new")))
            assertTrue("master" in engine.liveAliases(), "adoption must not sweep the live g1 key")
            assertEquals("old-value", upgraded.getRaw("old", "", String.serializer()))
            assertEquals("new-value", upgraded.getRaw("new", "", String.serializer()))

            // On the following launch the record is no longer ambiguous. Normal MaxAge
            // policy may now act and finish both entries, proving migration delayed rather
            // than disabled rotation.
            upgraded.cancel()
            buildCore(storage, engine, lazyLoad = false, config = policy)
            withTimeout(10.seconds) {
                while (
                    KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)) != 3 ||
                    KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))) != 3 ||
                    KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("new"))) != 3 ||
                    KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
                ) {
                    delay(20)
                }
            }
            assertEquals(0, KeySafeMetadataManager.parseKeyRotationLifecycle(storage.text(keygenKey)))
        }

    @Test
    fun coalesced30Adoption_cannotDisplaceAConcurrent31GenerationBump() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":123}"""))
        val core = buildCore(storage, engine)
        core.startupCleanupDone.set(true)

        // Dangerous queue order: the newer g3/r1 bump is followed by the lower g2/r0
        // adoption in the SAME batch. The coalescer must retain the generation authority,
        // not apply ordinary "last raw key wins".
        core.processWrites(
            listOf(
                KSafeCore.PendingWrite.SetKeyGeneration(
                    generation = 3,
                    timestampMillis = 300,
                    rotationInProgress = true,
                    completion = CompletableDeferred(),
                ),
                KSafeCore.PendingWrite.SetKeyGeneration(
                    generation = 2,
                    timestampMillis = 123,
                    completion = CompletableDeferred(),
                ),
            )
        )

        assertEquals("""{"g":3,"ts":300,"r":1}""", storage.text(keygenKey))
        assertEquals(3, core.currentKeyGeneration.get())
    }

    @Test
    fun completedRecordWithoutRetryMarker_doesNotAutoResume_underNeverPolicy() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("skipped", "old-value", KSafeWriteMode.Encrypted(), String.serializer())

        // A 3.0 record adopted by early 3.1 startup can be r:0 with an older entry but no
        // retry marker. Absence of rp must stay conservative: it is not evidence that a
        // retryable 3.1 pass was skipped.
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0}"""))
        creator.putRaw("current", "new-value", KSafeWriteMode.Encrypted(), String.serializer())
        val skippedCiphertext = storage.text(valueKey("skipped"))
        val skippedMetadata = storage.text(metaKey("skipped"))
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(skippedMetadata))
        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("current"))))
        creator.cancel()

        val reopened = buildCore(storage, engine, lazyLoad = false) // default policy = Never
        // Startup maintenance is asynchronous. Give an incorrect r:0-as-resume
        // implementation enough time to expose itself.
        delay(200)

        assertEquals("""{"g":2,"ts":123,"r":0}""", storage.text(keygenKey))
        assertEquals(skippedCiphertext, storage.text(valueKey("skipped")))
        assertEquals(skippedMetadata, storage.text(metaKey("skipped")))
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("skipped"))))
        assertEquals("old-value", reopened.getRaw("skipped", "", String.serializer()))
        assertEquals("new-value", reopened.getRaw("current", "", String.serializer()))
    }

    @Test
    fun pendingRetry_isConsumedImmediatelyByTheNextInstance_evenUnderNever() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("skipped", "old-value", KSafeWriteMode.Encrypted(), String.serializer())

        storage.seed(
            keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0,"rp":3}""")
        )
        creator.putRaw("current", "new-value", KSafeWriteMode.Encrypted(), String.serializer())
        creator.cancel()

        val reopened = buildCore(storage, engine, lazyLoad = false)
        withTimeout(10.seconds) {
            while (
                KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("skipped"))) != 2 ||
                KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey)) ||
                KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey))
            ) {
                delay(20)
            }
        }

        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)))
        assertEquals(123L, KeySafeMetadataManager.parseKeyGenerationTimestamp(storage.text(keygenKey)))
        assertEquals("old-value", reopened.getRaw("skipped", "", String.serializer()))
        assertEquals("new-value", reopened.getRaw("current", "", String.serializer()))
    }

    @Test
    fun maxAgePassSkippedByDeviceLock_waitsForTheNextInstance_thenRetriesUnderNever() =
        runBlocking {
            val storage = InMemoryStorage()
            val engine = LockableStatefulEncryption()
            val creator = buildCore(storage, engine)
            creator.startupCleanupDone.set(true)
            creator.putRaw(
                key = "locked",
                value = "secret",
                mode = KSafeWriteMode.Encrypted(requireUnlockedDevice = true),
                serializer = String.serializer(),
            )
            storage.seed(
                keygenKey to StoredValue.Text("""{"g":1,"ts":1,"r":0}""")
            )
            creator.cancel()

            engine.locked = true
            val scheduled = buildCore(
                storage = storage,
                engine = engine,
                lazyLoad = false,
                config = KSafeConfig(
                    keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(1.milliseconds)
                ),
            )
            withTimeout(10.seconds) {
                while (
                    KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)) != 2 ||
                    KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey)) ||
                    KeySafeMetadataManager.parseKeyRotationRetryAttempts(
                        storage.text(keygenKey)
                    ) != 3
                ) {
                    delay(20)
                }
            }
            assertEquals(
                1,
                KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("locked"))),
                "the locked entry stays readable under its old generation",
            )
            val generationBirth =
                KeySafeMetadataManager.parseKeyGenerationTimestamp(storage.text(keygenKey))
            assertTrue(generationBirth != null)

            // Unlocking during this SAME app run does not create a timer or an in-process loop.
            engine.locked = false
            delay(200)
            assertEquals(
                1,
                KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("locked"))),
            )
            assertEquals(
                3,
                KeySafeMetadataManager.parseKeyRotationRetryAttempts(storage.text(keygenKey)),
            )
            scheduled.cancel()

            // The next KSafe instance consumes the marker immediately, even under Never.
            val reopened = buildCore(storage, engine, lazyLoad = false)
            withTimeout(10.seconds) {
                while (
                    KeySafeMetadataManager.parseKeyGeneration(
                        storage.text(metaKey("locked"))
                    ) != 2 ||
                    KeySafeMetadataManager.parseKeyRotationLifecycle(
                        storage.text(keygenKey)
                    ) != 0 ||
                    KeySafeMetadataManager.hasKeyRotationRetryPending(
                        storage.text(keygenKey)
                    )
                ) {
                    delay(20)
                }
            }

            assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)))
            assertEquals(generationBirth, KeySafeMetadataManager.parseKeyGenerationTimestamp(storage.text(keygenKey)))
            assertEquals("secret", reopened.getRaw("locked", "", String.serializer()))
        }

    @Test
    fun retryWhileStillLocked_consumesTheBoundedBudget_withoutSameInstanceLoop() =
        runBlocking {
            val storage = InMemoryStorage()
            val engine = LockableStatefulEncryption()
            val creator = buildCore(storage, engine)
            creator.startupCleanupDone.set(true)
            creator.putRaw(
                key = "locked",
                value = "secret",
                mode = KSafeWriteMode.Encrypted(requireUnlockedDevice = true),
                serializer = String.serializer(),
            )
            storage.seed(
                keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0,"rp":3}""")
            )
            creator.cancel()

            engine.locked = true
            val firstRetry = buildCore(storage, engine, lazyLoad = false)
            withTimeout(10.seconds) {
                while (storage.inProgressKeygenWrites < 1) delay(20)
            }
            withTimeout(10.seconds) {
                while (KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))) {
                    delay(20)
                }
            }
            val attemptsAfterCompletion = engine.lockedDecryptAttempts
            delay(200)

            assertEquals("""{"g":2,"ts":123,"r":0,"rp":2}""", storage.text(keygenKey))
            assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("locked"))))
            assertEquals(
                attemptsAfterCompletion,
                engine.lockedDecryptAttempts,
                "the same instance must not start a timer or retry loop after completion",
            )
            firstRetry.cancel()

            val claimsBeforeSecond = storage.inProgressKeygenWrites
            val secondRetry = buildCore(storage, engine, lazyLoad = false)
            withTimeout(10.seconds) {
                while (storage.inProgressKeygenWrites <= claimsBeforeSecond) delay(20)
            }
            withTimeout(10.seconds) {
                while (KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))) {
                    delay(20)
                }
            }
            assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)))
            assertEquals(
                1,
                KeySafeMetadataManager.parseKeyRotationRetryAttempts(storage.text(keygenKey)),
            )
            secondRetry.cancel()

            val claimsBeforeLast = storage.inProgressKeygenWrites
            val lastRetry = buildCore(storage, engine, lazyLoad = false)
            withTimeout(10.seconds) {
                while (storage.inProgressKeygenWrites <= claimsBeforeLast) delay(20)
            }
            withTimeout(10.seconds) {
                while (KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))) {
                    delay(20)
                }
            }
            assertFalse(KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey)))
            lastRetry.cancel()

            val claimsAfterBudget = storage.inProgressKeygenWrites
            val noFourthRetry = buildCore(storage, engine, lazyLoad = false)
            delay(200)
            assertEquals(
                claimsAfterBudget,
                storage.inProgressKeygenWrites,
                "the exhausted budget must not restart on a later instance",
            )
            noFourthRetry.cancel()
        }

    @Test
    fun customRetryBudget_isPersisted_andZeroDisablesArming() = runBlocking {
        suspend fun rotateLocked(retryAttempts: Int): String {
            val storage = InMemoryStorage()
            val engine = LockableStatefulEncryption()
            val core = buildCore(
                storage = storage,
                engine = engine,
                config = KSafeConfig(keyRotationRetryAttempts = retryAttempts),
            )
            core.startupCleanupDone.set(true)
            core.putRaw(
                key = "locked",
                value = "secret",
                mode = KSafeWriteMode.Encrypted(requireUnlockedDevice = true),
                serializer = String.serializer(),
            )
            engine.locked = true
            val result = core.rotateKeys()
            assertEquals(1, result.skipped)
            val raw = storage.text(keygenKey)!!
            core.cancel()
            return raw
        }

        val customRaw = rotateLocked(5)
        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(customRaw))
        assertEquals(5, KeySafeMetadataManager.parseKeyRotationRetryAttempts(customRaw))

        val disabledRaw = rotateLocked(0)
        assertFalse(KeySafeMetadataManager.hasKeyRotationRetryPending(disabledRaw))
    }

    @Test
    fun zeroRetryConfig_pausesAnAlreadyPersistedBudget_withoutErasingIt() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("old", "value", KSafeWriteMode.Encrypted(), String.serializer())
        storage.seed(
            keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0,"rp":3}""")
        )
        creator.cancel()

        val reopened = buildCore(
            storage = storage,
            engine = engine,
            lazyLoad = false,
            config = KSafeConfig(keyRotationRetryAttempts = 0),
        )
        delay(200)

        assertEquals("""{"g":2,"ts":123,"r":0,"rp":3}""", storage.text(keygenKey))
        assertEquals(0, storage.inProgressKeygenWrites)
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))))
        reopened.cancel()
    }

    @Test
    fun crashRecoveryOfFinalClaimedRetry_doesNotRefillTheBudget() = runBlocking {
        val storage = InMemoryStorage()
        val engine = LockableStatefulEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw(
            key = "locked",
            value = "secret",
            mode = KSafeWriteMode.Encrypted(requireUnlockedDevice = true),
            serializer = String.serializer(),
        )
        // This is the durable state left when the last remaining attempt was decremented
        // before work and the process then died: the claimed retry still needs crash
        // recovery, but no later normally-completed retry remains.
        storage.seed(
            keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":1,"rp":0}""")
        )
        creator.cancel()

        engine.locked = true
        val reopened = buildCore(storage, engine, lazyLoad = false)
        withTimeout(10.seconds) {
            while (
                KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
            ) {
                delay(20)
            }
        }

        assertFalse(
            KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey)),
            "crash recovery of the last claimed retry must finish without restoring rp",
        )
        reopened.cancel()

        val retryClaimsAfterRecovery = storage.inProgressKeygenWrites
        val later = buildCore(storage, engine, lazyLoad = false)
        delay(200)
        assertEquals(retryClaimsAfterRecovery, storage.inProgressKeygenWrites)
        assertFalse(KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey)))
        later.cancel()
    }

    @Test
    fun pendingRetry_whenMaxAgeIsAlreadyDue_startsFreshGenerationInstead() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("old", "value", KSafeWriteMode.Encrypted(), String.serializer())
        storage.seed(
            keygenKey to StoredValue.Text("""{"g":2,"ts":1,"r":0,"rp":3}""")
        )
        creator.cancel()

        val reopened = buildCore(
            storage = storage,
            engine = engine,
            lazyLoad = false,
            config = KSafeConfig(
                keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(1.milliseconds),
                keyRotationRetryAttempts = 0,
            ),
        )
        withTimeout(10.seconds) {
            while (
                KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)) != 3 ||
                KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
            ) {
                delay(20)
            }
        }

        assertEquals(3, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))))
        assertFalse(KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey)))
        assertEquals("value", reopened.getRaw("old", "", String.serializer()))
    }

    @Test
    fun sameGenerationRetryClaim_isCompareAndSet_andOnlyOneClaimWins() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        storage.seed(
            keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0,"rp":3}""")
        )
        val core = buildCore(storage, engine)
        core.startupCleanupDone.set(true)

        val first = KSafeCore.PendingWrite.SetKeyGeneration(
            generation = 2,
            timestampMillis = 123,
            rotationInProgress = true,
            claimPendingRetry = true,
            completion = CompletableDeferred(),
        )
        val second = KSafeCore.PendingWrite.SetKeyGeneration(
            generation = 2,
            timestampMillis = 123,
            rotationInProgress = true,
            claimPendingRetry = true,
            completion = CompletableDeferred(),
        )
        core.processWrites(listOf(first, second))

        assertFalse(first.applied.get(), "the coalesced-out retry claimant must not run")
        assertTrue(second.applied.get(), "exactly one claimant owns the durable retry")
        assertEquals("""{"g":2,"ts":123,"r":1,"rp":2}""", storage.text(keygenKey))
    }

    @Test
    fun unknownRotationLifecycle_isPreserved_andManualRotationFailsClosed() = runBlocking {
        for (
            future in listOf(
                """{"g":2,"ts":123,"r":2}""",
                """{"g":2,"ts":123,"r":"future"}""",
                """{"g":2,"ts":123,"r":0,"rp":"future"}""",
                """{"g":2,"ts":123,"r":0,"rp":0}""",
                """{"g":2,"ts":123,"r":0,"rp":-1}""",
                """{"g":2,"ts":123,"r":1,"rp":-1}""",
                "garbage",
            )
        ) {
            val storage = InMemoryStorage()
            val engine = StatefulFakeEncryption()
            storage.seed(keygenKey to StoredValue.Text(future))
            val core = buildCore(storage, engine)
            core.startupCleanupDone.set(true)
            withTimeout(10.seconds) {
                while (!engine.liveAliases().containsAll(listOf("master", "master_locked"))) delay(10)
            }
            val aliasesBefore = engine.liveAliases()

            val error = assertFailsWith<IllegalStateException> { core.rotateKeys() }

            assertTrue("unsupported key-rotation lifecycle" in error.message.orEmpty())
            assertEquals(future, storage.text(keygenKey))
            assertEquals(
                aliasesBefore,
                engine.liveAliases(),
                "unknown lifecycle state must mint/delete no additional keys",
            )
            core.cancel()
        }
    }

    @Test
    fun cancelledPass_persistsRecoveryMarker_andNextInstanceFinishesIt() = runBlocking {
        val storage = InMemoryStorage()
        val engine = GatedStatefulEncryption()
        val original = buildCore(storage, engine)
        // Keep this test's gate exclusively on the rotation decrypt, not the lazy startup
        // orphan probe which is exercised independently elsewhere.
        original.startupCleanupDone.set(true)
        original.putRaw("old", "old-value", KSafeWriteMode.Encrypted(), String.serializer())

        engine.gateArmed = true
        val interrupted = async(Dispatchers.Default) { original.rotateKeys() }
        withTimeout(10.seconds) { engine.decryptEntered.await() }

        val during = storage.text(keygenKey)
        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(during))
        assertTrue(
            KeySafeMetadataManager.parseKeyRotationInProgress(during),
            "the generation bump must durably mark the pass before the first entry moves",
        )

        // Coroutine cancellation models process death at the only granularity a unit test
        // can observe: the pass stops without running its sweep/completion tail.
        interrupted.cancel()
        assertFailsWith<CancellationException> { interrupted.await() }
        engine.gateArmed = false

        // A write landing after the bump already belongs to g2, giving the exact mixed
        // old+new-generation store described by the public crash guarantee.
        original.putRaw("new", "new-value", KSafeWriteMode.Encrypted(), String.serializer())
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))))
        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("new"))))
        original.cancel()

        val reopened = buildCore(storage, engine, lazyLoad = false)
        withTimeout(10.seconds) {
            while (
                KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))) != 2 ||
                KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
            ) {
                delay(20)
            }
        }

        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)))
        assertEquals("old-value", reopened.getRaw("old", "", String.serializer()))
        assertEquals("new-value", reopened.getRaw("new", "", String.serializer()))
    }

    @Test
    fun nextInstance_resumesCrashInterruptedRotation_atTheSameGeneration_underNeverPolicy() =
        runBlocking {
            val storage = InMemoryStorage()
            val engine = StatefulFakeEncryption()

            // Fabricate the exact durable state a process can leave after it bumped to g2:
            // one older v2/g1 entry, one write that already landed at v3/g2, and the
            // store-level "rotation still in progress" marker. Both generations' master
            // keys exist, so the mixed store is readable before recovery.
            val oldJson = "\"old-value\""
            val oldCiphertext = engine.encrypt(
                identifier = "master",
                data = oldJson.encodeToByteArray(),
                hardwareIsolated = false,
                requireUnlockedDevice = false,
                aad = null,
            )
            val newJson = "\"new-value\""
            val newCiphertext = engine.encrypt(
                identifier = "master.g2",
                data = newJson.encodeToByteArray(),
                hardwareIsolated = false,
                requireUnlockedDevice = false,
                aad = KeySafeMetadataManager.aadFor(
                    storeIdentity = "",
                    userKey = "new",
                    protection = KSafeProtection.DEFAULT,
                    requireUnlockedDevice = false,
                    keyGeneration = 2,
                ),
            )
            storage.seed(
                valueKey("old") to StoredValue.Text(KSafeBase64.encode(oldCiphertext)),
                metaKey("old") to StoredValue.Text(
                    KeySafeMetadataManager.buildMetadataJson(
                        protection = KSafeProtection.DEFAULT,
                        accessPolicy = null,
                        envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_V2,
                        keyGeneration = 1,
                    )
                ),
                valueKey("new") to StoredValue.Text(KSafeBase64.encode(newCiphertext)),
                metaKey("new") to StoredValue.Text(
                    KeySafeMetadataManager.buildMetadataJson(
                        protection = KSafeProtection.DEFAULT,
                        accessPolicy = null,
                        envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_V3,
                        keyGeneration = 2,
                    )
                ),
                keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":1}"""),
            )

            // Constructing the next eager instance is enough. KSafeConfig() uses Never:
            // crash recovery is lifecycle repair, not a scheduled-rotation policy.
            val reopened = buildCore(storage, engine, lazyLoad = false)
            withTimeout(10.seconds) {
                while (
                    KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))) != 2 ||
                    KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
                ) {
                    delay(20)
                }
            }

            assertEquals(
                2,
                KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)),
                "resume must finish g2, not create an unrelated g3 rotation",
            )
            assertFalse(
                KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey)),
                "the marker reaches r:0 only after entry commits and the master sweep finish",
            )
            assertEquals("old-value", reopened.getRaw("old", "", String.serializer()))
            assertEquals("new-value", reopened.getRaw("new", "", String.serializer()))
            assertFalse(
                "master" in engine.liveAliases(),
                "the resumed final sweep reclaims the now-unreferenced g1 master",
            )
            assertTrue("master.g2" in engine.liveAliases())
        }

    @Test
    fun staleCompletion_cannotClearANewerRotationsRecoveryMarker() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val newer = """{"g":3,"ts":300,"r":1}"""
        storage.seed(keygenKey to StoredValue.Text(newer))
        val core = buildCore(storage, engine)
        core.startupCleanupDone.set(true)

        val completed = CompletableDeferred<Unit>()
        core.writeChannel.send(
            KSafeCore.PendingWrite.CompleteKeyRotation(
                generation = 2,
                completion = completed,
            )
        )
        completed.await()

        assertEquals(
            newer,
            storage.text(keygenKey),
            "a generation-2 tail must not acknowledge/erase generation 3's recovery state",
        )
    }

    @Test
    fun maxAgeBirthStamp_preservesAnExistingRecoveryMarker() = runBlocking {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"r":1}"""))
        val core = buildCore(storage, engine)
        core.startupCleanupDone.set(true)

        val stamped = CompletableDeferred<Unit>()
        core.writeChannel.send(
            KSafeCore.PendingWrite.SetKeyGeneration(
                generation = 2,
                timestampMillis = 456,
                completion = stamped,
            )
        )
        stamped.await()

        assertEquals(456L, KeySafeMetadataManager.parseKeyGenerationTimestamp(storage.text(keygenKey)))
        assertTrue(
            KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey)),
            "filling a missing age timestamp must never disarm crash recovery",
        )
    }

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

    @Test
    fun staleRotation_cannotStampAnEntryLeftBehindAtAnOlderGeneration() = runBlocking {
        val storage = InMemoryStorage()
        val engine = LockableStatefulEncryption()
        val core = buildCore(storage, engine)
        core.startupCleanupDone.set(true)

        core.putRaw("free", "v1", KSafeWriteMode.Encrypted(), String.serializer())
        core.putRaw(
            key = "locked",
            value = "secret",
            mode = KSafeWriteMode.Encrypted(requireUnlockedDevice = true),
            serializer = String.serializer(),
        )

        // Two passes with the device locked leave "locked" behind at generation 1 while the
        // store's authority advances to 3 — the candidate the sibling test never has.
        engine.locked = true
        assertEquals(2, core.rotateKeys().keyGeneration)
        assertEquals(3, core.rotateKeys().keyGeneration)
        engine.locked = false
        val persistedAtG3 = storage.text(keygenKey)!!
        assertEquals(3, KeySafeMetadataManager.parseKeyGeneration(persistedAtG3))

        core.currentKeyGeneration.set(1)
        val stale = core.rotateKeys()

        assertEquals(
            persistedAtG3, storage.text(keygenKey),
            "a stale pass must leave the record — including its retry budget — untouched",
        )
        assertEquals(
            0, stale.rotated,
            "an entry behind the authority must not be re-stamped with the stale target",
        )
        assertEquals(1, stale.skipped)
        assertEquals("v1", core.getRaw("free", "MISSING", String.serializer()))
        assertEquals("secret", core.getRaw("locked", "MISSING", String.serializer()))

        // Now unlocked and reconciled, an honest pass collects both entries.
        val honest = core.rotateKeys()
        assertEquals(4, honest.keyGeneration)
        assertEquals(2, honest.rotated)
        assertEquals("v1", core.getRaw("free", "MISSING", String.serializer()))
        assertEquals("secret", core.getRaw("locked", "MISSING", String.serializer()))
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
        assertFalse(
            KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey)),
            "a definitive failure alone must not arm the automatic retry loop",
        )
        assertEquals(junk, storage.text(valueKey("future")), "the ciphertext must stay untouched")
    }
}
