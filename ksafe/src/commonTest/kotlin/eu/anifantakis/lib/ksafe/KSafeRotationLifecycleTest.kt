package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.coreparts.processWrites
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.builtins.serializer
import kotlin.concurrent.Volatile
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The rotation lifecycle invariants, exercised on EVERY target rather than on the JVM alone.
 *
 * The state machine lives in commonMain, but its coroutine behaviour does not: web is
 * single-threaded, native has its own memory model, and Android runs the same code on a different
 * dispatcher. `JvmGenerationAuthorityTest` remains the exhaustive suite; this one carries the cases
 * whose failure would be silent and unrecoverable — crash resume, the bounded retry claim, and the
 * conservative adoption of a 3.0.0 record — so they are proven wherever KSafe ships.
 *
 * Storage here is an in-memory fake, so this suite proves the machine, not the substrate: real
 * write atomicity and cross-instance exclusion remain a per-backend property.
 */
class KSafeRotationLifecycleTest {

    private val keygenKey = KeySafeMetadataManager.KEYGEN_RAW_KEY
    private val cores = mutableListOf<KSafeCore>()

    @AfterTest
    fun tearDown() {
        cores.forEach { it.cancel() }
        cores.clear()
    }

    private class InMemoryStorage : KSafePlatformStorage {
        private val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())

        /** Counts durable rotation claims, so "did a second pass start?" is directly observable. */
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
        fun text(rawKey: String): String? = (state.value[rawKey] as? StoredValue.Text)?.value
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

    /**
     * Startup maintenance runs on a background scope, so these assertions need real elapsed time.
     * `runTest`'s virtual clock would spin the poll loop to its deadline without ever yielding to
     * that scope, hence the hop onto a real dispatcher.
     */
    private suspend fun awaitUntil(
        what: String,
        timeout: Duration = 10.seconds,
        condition: () -> Boolean,
    ) {
        withContext(Dispatchers.Default) {
            try {
                withTimeout(timeout) { while (!condition()) delay(20) }
            } catch (_: TimeoutCancellationException) {
                fail("timed out after $timeout waiting for: $what")
            }
        }
    }

    /** Real elapsed time, for "a wrong implementation would have acted by now" waits. */
    private suspend fun settle(duration: Duration = 200.milliseconds) {
        withContext(Dispatchers.Default) { delay(duration) }
    }

    // ---- crash resume ---------------------------------------------------------------------

    @Test
    fun nextInstanceResumesCrashInterruptedRotationAtTheSameGeneration() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()

        // The exact durable state a process can leave after bumping to g2: one older v2/g1 entry,
        // one write that already landed at v3/g2, and the in-progress marker. Both masters exist,
        // so the mixed store is readable before recovery.
        val oldCiphertext = engine.encrypt(
            identifier = "master",
            data = "\"old-value\"".encodeToByteArray(),
            hardwareIsolated = false,
            requireUnlockedDevice = false,
            aad = null,
        )
        val newCiphertext = engine.encrypt(
            identifier = "master.g2",
            data = "\"new-value\"".encodeToByteArray(),
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

        // Constructing the next eager instance is enough: KSafeConfig() is Never, because crash
        // recovery is lifecycle repair rather than a scheduled-rotation policy.
        val reopened = buildCore(storage, engine, lazyLoad = false)
        awaitUntil("the interrupted g2 pass to finish and disarm") {
            KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))) == 2 &&
                !KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
        }

        assertEquals(
            2,
            KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)),
            "resume must finish g2, not create an unrelated g3 rotation",
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
    fun crashRecoveryOfFinalClaimedRetryDoesNotRefillTheBudget() = runTest {
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
        // The durable state left when the last remaining attempt was decremented before work and
        // the process then died: the claimed retry still needs crash recovery, but no later
        // normally-completed retry remains.
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":1,"rp":0}"""))
        creator.cancel()

        engine.locked = true
        val reopened = buildCore(storage, engine, lazyLoad = false)
        awaitUntil("crash recovery of the final claimed retry to disarm") {
            !KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
        }

        assertFalse(
            KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey)),
            "crash recovery of the last claimed retry must finish without restoring rp",
        )
        reopened.cancel()

        val claimsAfterRecovery = storage.inProgressKeygenWrites
        buildCore(storage, engine, lazyLoad = false)
        settle()
        assertEquals(claimsAfterRecovery, storage.inProgressKeygenWrites)
        assertFalse(KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey)))
    }

    // ---- the bounded retry claim ----------------------------------------------------------

    @Test
    fun pendingRetryIsConsumedByTheNextInstanceEvenUnderNever() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("skipped", "old-value", KSafeWriteMode.Encrypted(), String.serializer())

        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0,"rp":3}"""))
        creator.putRaw("current", "new-value", KSafeWriteMode.Encrypted(), String.serializer())
        creator.cancel()

        val reopened = buildCore(storage, engine, lazyLoad = false)
        awaitUntil("the pending retry to be claimed and finished") {
            KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("skipped"))) == 2 &&
                !KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey)) &&
                !KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey))
        }

        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)))
        assertEquals(
            123L,
            KeySafeMetadataManager.parseKeyGenerationTimestamp(storage.text(keygenKey)),
            "a retry must not reset the generation-birth clock",
        )
        assertEquals("old-value", reopened.getRaw("skipped", "", String.serializer()))
        assertEquals("new-value", reopened.getRaw("current", "", String.serializer()))
    }

    @Test
    fun maxAgePassSkippedByDeviceLockWaitsForTheNextInstance() = runTest {
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
        storage.seed(keygenKey to StoredValue.Text("""{"g":1,"ts":1,"r":0}"""))
        creator.cancel()

        engine.locked = true
        val scheduled = buildCore(
            storage = storage,
            engine = engine,
            lazyLoad = false,
            config = KSafeConfig(keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(1.milliseconds)),
        )
        awaitUntil("the locked pass to complete and arm a retry budget") {
            KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)) == 2 &&
                !KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey)) &&
                KeySafeMetadataManager.parseKeyRotationRetryAttempts(storage.text(keygenKey)) == 3
        }
        assertEquals(
            1,
            KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("locked"))),
            "the locked entry stays readable under its old generation",
        )
        val generationBirth =
            KeySafeMetadataManager.parseKeyGenerationTimestamp(storage.text(keygenKey))
        assertTrue(generationBirth != null)

        // Unlocking during this SAME run must not create a timer or an in-process retry loop.
        engine.locked = false
        settle()
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("locked"))))
        assertEquals(3, KeySafeMetadataManager.parseKeyRotationRetryAttempts(storage.text(keygenKey)))
        scheduled.cancel()

        // The next instance consumes the marker immediately, even under Never.
        val reopened = buildCore(storage, engine, lazyLoad = false)
        awaitUntil("the next instance to consume the pending retry") {
            KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("locked"))) == 2 &&
                KeySafeMetadataManager.parseKeyRotationLifecycle(storage.text(keygenKey)) == 0 &&
                !KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey))
        }

        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)))
        assertEquals(
            generationBirth,
            KeySafeMetadataManager.parseKeyGenerationTimestamp(storage.text(keygenKey)),
        )
        assertEquals("secret", reopened.getRaw("locked", "", String.serializer()))
    }

    @Test
    fun retryWhileStillLockedConsumesTheBoundedBudget() = runTest {
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
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0,"rp":3}"""))
        creator.cancel()

        engine.locked = true
        val firstRetry = buildCore(storage, engine, lazyLoad = false)
        awaitUntil("the first retry claim to land") { storage.inProgressKeygenWrites >= 1 }
        awaitUntil("the first retry to complete") {
            !KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
        }
        val attemptsAfterCompletion = engine.lockedDecryptAttempts
        settle()

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
        awaitUntil("the second retry claim") { storage.inProgressKeygenWrites > claimsBeforeSecond }
        awaitUntil("the second retry to complete") {
            !KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
        }
        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)))
        assertEquals(1, KeySafeMetadataManager.parseKeyRotationRetryAttempts(storage.text(keygenKey)))
        secondRetry.cancel()

        val claimsBeforeLast = storage.inProgressKeygenWrites
        val lastRetry = buildCore(storage, engine, lazyLoad = false)
        awaitUntil("the final retry claim") { storage.inProgressKeygenWrites > claimsBeforeLast }
        awaitUntil("the final retry to complete") {
            !KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
        }
        assertFalse(KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey)))
        lastRetry.cancel()

        val claimsAfterBudget = storage.inProgressKeygenWrites
        buildCore(storage, engine, lazyLoad = false)
        settle()
        assertEquals(
            claimsAfterBudget,
            storage.inProgressKeygenWrites,
            "the exhausted budget must not restart on a later instance",
        )
    }

    @Test
    fun customRetryBudgetIsPersistedAndZeroDisablesArming() = runTest {
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
            assertEquals(1, core.rotateKeys().skipped)
            val raw = storage.text(keygenKey)!!
            core.cancel()
            return raw
        }

        val customRaw = rotateLocked(5)
        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(customRaw))
        assertEquals(5, KeySafeMetadataManager.parseKeyRotationRetryAttempts(customRaw))

        assertFalse(KeySafeMetadataManager.hasKeyRotationRetryPending(rotateLocked(0)))
    }

    @Test
    fun zeroRetryConfigPausesAnAlreadyPersistedBudgetWithoutErasingIt() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("old", "value", KSafeWriteMode.Encrypted(), String.serializer())
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0,"rp":3}"""))
        creator.cancel()

        buildCore(
            storage = storage,
            engine = engine,
            lazyLoad = false,
            config = KSafeConfig(keyRotationRetryAttempts = 0),
        )
        settle()

        assertEquals("""{"g":2,"ts":123,"r":0,"rp":3}""", storage.text(keygenKey))
        assertEquals(0, storage.inProgressKeygenWrites)
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))))
    }

    @Test
    fun pendingRetryWhenMaxAgeIsAlreadyDueStartsFreshGenerationInstead() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("old", "value", KSafeWriteMode.Encrypted(), String.serializer())
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":1,"r":0,"rp":3}"""))
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
        awaitUntil("the due MaxAge pass to take precedence and reach g3") {
            KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)) == 3 &&
                !KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
        }

        assertEquals(3, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))))
        assertFalse(KeySafeMetadataManager.hasKeyRotationRetryPending(storage.text(keygenKey)))
        assertEquals("value", reopened.getRaw("old", "", String.serializer()))
    }

    // ---- generation authority under coalescing ---------------------------------------------

    @Test
    fun sameGenerationRetryClaimIsCompareAndSetAndOnlyOneClaimWins() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0,"rp":3}"""))
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
    fun staleCompletionCannotClearANewerRotationsRecoveryMarker() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val newer = """{"g":3,"ts":300,"r":1}"""
        storage.seed(keygenKey to StoredValue.Text(newer))
        val core = buildCore(storage, engine)
        core.startupCleanupDone.set(true)

        val completed = CompletableDeferred<Unit>()
        core.writeChannel.send(
            KSafeCore.PendingWrite.CompleteKeyRotation(generation = 2, completion = completed)
        )
        completed.await()

        assertEquals(
            newer,
            storage.text(keygenKey),
            "a generation-2 tail must not acknowledge or erase generation 3's recovery state",
        )
    }

    @Test
    fun maxAgeBirthStampPreservesAnExistingRecoveryMarker() = runTest {
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

    // ---- a metadata record whose value never landed ----------------------------------------

    /**
     * The web batch ordering deliberately lets metadata survive a tear without its value. Such a
     * record is invisible to both reapers — rotation needs a ciphertext to build a candidate, and
     * the orphan sweep enumerates value records — so if the master sweep counts it as a live
     * reference, the superseded master is never retired and rotation silently stops achieving the
     * one thing it exists for.
     */
    @Test
    fun metadataWithoutItsValueDoesNotPinASupersededMaster() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val core = buildCore(storage, engine)
        core.startupCleanupDone.set(true) // isolate the sweep: no startup reaping in this test
        core.putRaw("real", "value", KSafeWriteMode.Encrypted(), String.serializer())

        // The torn half: metadata at g1 with no value record under any layout.
        storage.seed(
            metaKey("phantom") to StoredValue.Text(
                KeySafeMetadataManager.buildMetadataJson(
                    protection = KSafeProtection.DEFAULT,
                    accessPolicy = null,
                    keyGeneration = 1,
                )
            )
        )

        assertEquals(1, core.rotateKeys().rotated, "only the real entry has ciphertext to rotate")

        assertFalse(
            "master" in engine.liveAliases(),
            "a metadata record with no value must not keep the superseded master alive",
        )
        assertTrue("master.g2" in engine.liveAliases())
    }

    @Test
    fun startupCleanupReapsMetadataWhoseValueNeverLanded() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("real", "value", KSafeWriteMode.Encrypted(), String.serializer())
        storage.seed(
            metaKey("phantom") to StoredValue.Text(
                KeySafeMetadataManager.buildMetadataJson(
                    protection = KSafeProtection.DEFAULT,
                    accessPolicy = null,
                    keyGeneration = 1,
                )
            )
        )
        creator.cancel()

        val reopened = buildCore(storage, engine, lazyLoad = false)
        awaitUntil("the value-less metadata record to be reaped") {
            storage.text(metaKey("phantom")) == null
        }

        assertEquals(
            "value",
            reopened.getRaw("real", "", String.serializer()),
            "reaping the phantom must not disturb a healthy entry",
        )
        assertTrue(storage.text(metaKey("real")) != null, "the healthy entry keeps its metadata")
    }

    // ---- conservative handling of records this version did not write ------------------------

    @Test
    fun completedRecordWithoutRetryMarkerDoesNotAutoResumeUnderNever() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("skipped", "old-value", KSafeWriteMode.Encrypted(), String.serializer())

        // A 3.0 record adopted by an earlier 3.1 startup is r:0 with an older entry but no retry
        // marker. Absence of rp is not evidence that a retryable pass was skipped.
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":123,"r":0}"""))
        creator.putRaw("current", "new-value", KSafeWriteMode.Encrypted(), String.serializer())
        val skippedCiphertext = storage.text(valueKey("skipped"))
        val skippedMetadata = storage.text(metaKey("skipped"))
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(skippedMetadata))
        creator.cancel()

        val reopened = buildCore(storage, engine, lazyLoad = false) // default policy = Never
        settle() // long enough for an r:0-as-resume implementation to expose itself

        assertEquals("""{"g":2,"ts":123,"r":0}""", storage.text(keygenKey))
        assertEquals(skippedCiphertext, storage.text(valueKey("skipped")))
        assertEquals(skippedMetadata, storage.text(metaKey("skipped")))
        assertEquals("old-value", reopened.getRaw("skipped", "", String.serializer()))
        assertEquals("new-value", reopened.getRaw("current", "", String.serializer()))
    }

    @Test
    fun first31LaunchAdopts30RotationAsCompletedWithoutTouchingEntries() = runTest {
        val storage = InMemoryStorage()
        val engine = StatefulFakeEncryption()
        val creator = buildCore(storage, engine)
        creator.startupCleanupDone.set(true)
        creator.putRaw("old", "old-value", KSafeWriteMode.Encrypted(), String.serializer())

        // The mixed-generation state 3.0.0 could leave after a crash: the store bumped to g2, a
        // later write already used g2, one older entry remains on g1. 3.0.0 had no lifecycle field,
        // so absence must be adopted as completed rather than guessed to be an interrupted pass.
        storage.seed(keygenKey to StoredValue.Text("""{"g":2,"ts":1}"""))
        creator.putRaw("new", "new-value", KSafeWriteMode.Encrypted(), String.serializer())
        val oldValueBefore = storage.text(valueKey("old"))
        val oldMetaBefore = storage.text(metaKey("old"))
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(oldMetaBefore))
        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("new"))))
        creator.cancel()

        val policy = KSafeConfig(keyRotationPolicy = KSafeKeyRotationPolicy.MaxAge(1.milliseconds))
        val upgraded = buildCore(storage, engine, lazyLoad = false, config = policy)
        awaitUntil("the 3.0.0 record to be adopted as completed") {
            KeySafeMetadataManager.parseKeyRotationLifecycle(storage.text(keygenKey)) == 0
        }
        // Enough real time for an accidental same-launch MaxAge fall-through to expose itself.
        settle()

        assertEquals("""{"g":2,"ts":1,"r":0}""", storage.text(keygenKey))
        assertEquals(oldValueBefore, storage.text(valueKey("old")))
        assertEquals(oldMetaBefore, storage.text(metaKey("old")))
        assertTrue("master" in engine.liveAliases(), "adoption must not sweep the live g1 key")
        assertEquals("old-value", upgraded.getRaw("old", "", String.serializer()))
        upgraded.cancel()

        // On the following launch the record is no longer ambiguous, so normal MaxAge policy may
        // act — proving migration delayed rather than disabled rotation.
        buildCore(storage, engine, lazyLoad = false, config = policy)
        awaitUntil("the following launch to run the deferred MaxAge rotation") {
            KeySafeMetadataManager.parseKeyGeneration(storage.text(keygenKey)) == 3 &&
                KeySafeMetadataManager.parseKeyGeneration(storage.text(metaKey("old"))) == 3 &&
                !KeySafeMetadataManager.parseKeyRotationInProgress(storage.text(keygenKey))
        }
        assertEquals(0, KeySafeMetadataManager.parseKeyRotationLifecycle(storage.text(keygenKey)))
    }

    @Test
    fun unknownRotationLifecycleIsPreservedAndManualRotationFailsClosed() = runTest {
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
            awaitUntil("both master aliases to exist for $future") {
                engine.liveAliases().containsAll(listOf("master", "master_locked"))
            }
            val aliasesBefore = engine.liveAliases()

            val error = assertFailsWith<IllegalStateException> { core.rotateKeys() }

            assertTrue("unsupported key-rotation lifecycle" in error.message.orEmpty())
            assertEquals(future, storage.text(keygenKey))
            assertEquals(
                aliasesBefore,
                engine.liveAliases(),
                "unknown lifecycle state must mint or delete no additional keys",
            )
            core.cancel()
        }
    }
}
