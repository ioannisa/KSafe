package eu.anifantakis.ksafe.compose

import androidx.compose.runtime.AbstractApplier
import androidx.compose.runtime.Composition
import androidx.compose.runtime.Recomposer
import androidx.compose.runtime.structuralEqualityPolicy
import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import eu.anifantakis.lib.ksafe.compose.KSafeComposeState
import eu.anifantakis.lib.ksafe.compose.KSafeComposeStateProvider
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
import eu.anifantakis.lib.ksafe.compose.rememberKSafeState
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Locks in what each persisted-state factory reconciles to when a persist fails: the value that
 * is durable at that moment, re-read with the last in-sync value as the read's OWN fallback.
 * A read that cannot resolve (a strict entry on a locked device, a deleted key) yields that
 * fallback; a stored value that merely equals the caller's default comes back as itself.
 *
 * `mutableStateOf` always worked this way. `rememberKSafeState` used to publish the caller's
 * default over intact data, and later the composition-time value over a legitimately stored
 * default. Both factories now share the rule, and the assertions stay as a pair so a change
 * that moves only one of them fails here. The deleted-key cases stand in for the locked-device
 * one because they reach the same read path without the crypto engine seam, which is internal
 * to `:ksafe`.
 */
class JvmFailedPersistFallbackTest {

    /** Applies nothing: this composition exists only to run `remember` and build the real saver. */
    private class NoOpApplier : AbstractApplier<Unit>(Unit) {
        override fun insertTopDown(index: Int, instance: Unit) {}
        override fun insertBottomUp(index: Int, instance: Unit) {}
        override fun remove(index: Int, count: Int) {}
        override fun move(from: Int, to: Int, count: Int) {}
        override fun onClear() {}
    }

    private companion object {
        private val testCounter = AtomicInteger(0)
        private val runId: String = System.currentTimeMillis().toString(36)

        /** DataStore forbids two instances on one file, so every test gets its own. */
        fun uniqueFileName(): String = "composefallback${runId}t${testCounter.incrementAndGet()}"

        const val KEY = "token"

        /** Distinct from DEFAULT, so the state starts in sync with a real stored value. */
        const val STORED = 1.0
        const val DEFAULT = 0.0

        /**
         * KSafe's default Json enables `allowSpecialFloatingPointValues` precisely so an
         * encrypted put of a special float does not crash; this instance keeps kotlinx's own
         * default instead, which makes writing one fail while serializing — a synchronous,
         * deterministic persist failure reachable from public API alone.
         */
        val STRICT_JSON = KSafeConfig(json = Json { ignoreUnknownKeys = true })
        val UNWRITABLE = Double.POSITIVE_INFINITY

        /** Encrypted, so the write routes through the JSON encoder that rejects the value. */
        val MODE = KSafeWriteMode.Encrypted()
    }

    /**
     * Seeds the key, then removes it, so the post-failure re-read has nothing to resolve and
     * must return whichever fallback the factory passed it.
     */
    private fun newKSafeWithVanishedEntry(): KSafe {
        val ksafe = KSafe(fileName = uniqueFileName(), config = STRICT_JSON)
        runBlocking { ksafe.put(KEY, STORED, MODE) }
        return ksafe
    }

    /**
     * Guards the premise of the two tests below. They can only observe a fallback if the persist
     * actually fails, and it must fail *synchronously* for them to assert without waiting. If
     * this store ever starts accepting the value, this fails first and says why.
     */
    @Test
    fun theSeededStore_failsAnEncryptedPersistSynchronously_forAnUnwritableValue() {
        val ksafe = KSafe(fileName = uniqueFileName(), config = STRICT_JSON)

        assertFailsWith<SerializationException>("the persist must fail while serializing, on the caller's thread") {
            ksafe.putDirect("premise", UNWRITABLE, MODE) { /* async failures never reach here */ }
        }

        ksafe.close()
    }

    @Test
    fun mutableStateOf_reconcilesToTheLastInSyncValue_whenTheDurableReReadCannotResolve() {
        val ksafe = newKSafeWithVanishedEntry()

        // scope = null and a non-default initial value ⇒ no observation coroutine and no
        // cold-start self-heal, so the reconcile is the only thing that can move this state.
        val delegate = ksafe.mutableStateOf(DEFAULT, key = KEY, mode = MODE)
            .provideDelegate(null, ::probeProperty)
        assertEquals(
            STORED, delegate.getValue(null, ::probeProperty),
            "sanity: the state must start in sync with the stored value",
        )

        runBlocking { ksafe.delete(KEY) }
        // The persist throws while serializing, so the saver's own catch reconciles before
        // this assignment returns — nothing here is asynchronous.
        delegate.setValue(null, ::probeProperty, UNWRITABLE)

        // If this ever reds, check WHY before touching the expectation: the deleted key here is a
        // stand-in for an undecryptable one (see the class KDoc), so republishing the last in-sync
        // value is the desired outcome for the case being documented, even though under a literal
        // delete it looks like resurrecting removed data.
        assertEquals(
            STORED, delegate.getValue(null, ::probeProperty),
            "mutableStateOf re-reads with the last in-sync value as its fallback, so a re-read " +
                "that cannot resolve keeps showing the value the state already held",
        )

        ksafe.close()
    }

    @Test
    fun rememberKSafeState_reconcilesToTheLastInSyncValue_whenTheDurableReReadCannotResolve() {
        val ksafe = newKSafeWithVanishedEntry()

        // rememberKSafeState is not itself @Composable, but its provideDelegate is, so the real
        // saver can only be built inside a composition. The recomposer is deliberately never
        // started: one setContent pass is all this needs, and it keeps the state's LaunchedEffect
        // from doing anything observable.
        val recomposer = Recomposer(EmptyCoroutineContext)
        val composition = Composition(NoOpApplier(), recomposer)
        lateinit var state: KSafeComposeState<Double>
        composition.setContent {
            state = ksafe.rememberKSafeState(DEFAULT, key = KEY, mode = MODE)
                .provideDelegate(null, ::probeProperty)
        }

        assertEquals(
            STORED, state.value,
            "sanity: the state must start in sync with the stored value",
        )

        runBlocking { ksafe.delete(KEY) }
        state.value = UNWRITABLE

        // Same caveat as above: the deleted key stands in for an undecryptable one, so keeping
        // the last in-sync value is the desired outcome for the case being documented.
        assertEquals(
            STORED, state.value,
            "rememberKSafeState reverts to the last in-sync value, keeping the value the state " +
                "already held instead of publishing the caller's default over intact data",
        )

        composition.dispose()
        recomposer.cancel()
        ksafe.close()
    }

    /**
     * The case the deleted-key tests cannot see: the durable value RESOLVES, and it is fresher
     * than anything the state last synced.
     *
     * `syncedValue` only advances when storage tells the state something — a successful write
     * never touches it — so with the default `observeExternalChanges = false` it stays pinned to
     * whatever the composition read at startup. Reverting to it rewinds past every write that did
     * reach disk; the user then edits from the stale value they were shown and overwrites the real
     * one. The rollback must prefer what storage holds and yield to the synced value only when the
     * read cannot resolve.
     */
    @Test
    fun rememberKSafeState_afterASuccessfulWrite_rollsBackToWhatIsOnDisk_notToTheStartupValue() {
        val ksafe = KSafe(fileName = uniqueFileName(), config = STRICT_JSON)
        runBlocking { ksafe.put(KEY, STORED, MODE) }

        val recomposer = Recomposer(EmptyCoroutineContext)
        val composition = Composition(NoOpApplier(), recomposer)
        lateinit var state: KSafeComposeState<Double>
        composition.setContent {
            state = ksafe.rememberKSafeState(DEFAULT, key = KEY, mode = MODE)
                .provideDelegate(null, ::probeProperty)
        }
        assertEquals(STORED, state.value, "sanity: the state starts in sync with the stored value")

        val persisted = 2.0
        state.value = persisted
        assertEquals(
            persisted, runBlocking { ksafe.get(KEY, DEFAULT) },
            "sanity: this write must reach disk, or the rollback below proves nothing",
        )

        state.value = UNWRITABLE

        assertEquals(
            persisted, state.value,
            "the rollback must land on the value that is on disk. Reverting to the startup value " +
                "shows a stale number over a newer durable one, and the next edit made from it " +
                "overwrites what was really stored",
        )

        composition.dispose()
        recomposer.cancel()
        ksafe.close()
    }

    /**
     * The twin of the test above, with the durable value indistinguishable from the caller's
     * default — a cleared text field, a zeroed counter, `false`.
     *
     * Storing the default is an ordinary write, so "the re-read came back as the default" cannot
     * mean "the re-read could not resolve". Deciding between them by value rewinds the state to
     * whatever the composition read at startup and re-pins the synced baseline there, while disk
     * holds the cleared value; the next edit is then made from a value the user already removed.
     */
    @Test
    fun rememberKSafeState_afterSuccessfullyStoringTheDefaultValue_rollsBackToDisk_notToTheStartupValue() {
        val ksafe = KSafe(fileName = uniqueFileName(), config = STRICT_JSON)
        runBlocking { ksafe.put(KEY, STORED, MODE) }

        val recomposer = Recomposer(EmptyCoroutineContext)
        val composition = Composition(NoOpApplier(), recomposer)
        lateinit var state: KSafeComposeState<Double>
        composition.setContent {
            state = ksafe.rememberKSafeState(DEFAULT, key = KEY, mode = MODE)
                .provideDelegate(null, ::probeProperty)
        }
        assertEquals(STORED, state.value, "sanity: the state starts in sync with the stored value")

        state.value = DEFAULT
        assertEquals(
            DEFAULT, runBlocking { ksafe.get(KEY, STORED) },
            "sanity: clearing the value must reach disk, or the rollback below proves nothing",
        )

        state.value = UNWRITABLE

        assertEquals(
            DEFAULT, state.value,
            "the rollback must land on the value that is on disk even when that value equals the " +
                "default: resurrecting the startup value shows data the user already cleared",
        )
        assertEquals(
            DEFAULT, state.lastSyncedValue,
            "and the synced baseline must follow it, or the next failure rewinds there again",
        )

        composition.dispose()
        recomposer.cancel()
        ksafe.close()
    }

    /**
     * The same scenario down the asynchronous route: the persist returns cleanly and reports its
     * failure later through `onWriteFailed`. The store seam is faked because the engine that fails
     * an encrypted commit asynchronously is internal to `:ksafe`.
     */
    @Test
    fun rememberKSafeState_asyncPersistFailure_afterStoringTheDefaultValue_rollsBackToDisk() {
        val (state, dispose) = asyncFailureScenario(legacyConstructor = false)

        assertEquals(
            "", state.value,
            "an asynchronously reported failure must also land on the cleared durable value",
        )
        assertEquals("", state.lastSyncedValue, "and re-pin the synced baseline to it")
        dispose()
    }

    /**
     * Call sites inlined against an older release bind the constructor without `readDurable`.
     * They keep the behaviour they were compiled against: a durable value equal to the default
     * is still treated as an unresolvable read.
     */
    @Test
    fun legacyInlinedCallSite_keepsThePreviousRollbackHeuristic() {
        val (state, dispose) = asyncFailureScenario(legacyConstructor = true)

        assertEquals("A", state.value, "deliberately locks the OLD outcome for binaries inlined before readDurable existed")
        assertEquals("A", state.lastSyncedValue, "the legacy path also re-pins the baseline to that value")
        dispose()
    }

    private fun asyncFailureScenario(legacyConstructor: Boolean): Pair<KSafeComposeState<String>, () -> Unit> {
        var durable = "A"
        var notifyFailure: ((Throwable) -> Unit)? = null
        val neverEmits = flow<String> { awaitCancellation() }
        val readInitial: (String) -> String = { durable }
        val writeValue: (String, String, (Throwable) -> Unit) -> Unit = { _, newValue, onWriteFailed ->
            if (newValue == "B") notifyFailure = onWriteFailed else durable = newValue
        }
        val provider = if (legacyConstructor) {
            KSafeComposeStateProvider(
                explicitKey = "draft",
                defaultValue = "",
                observeExternalChanges = false,
                policy = structuralEqualityPolicy(),
                instanceKey = null,
                modeKey = null,
                readInitial = readInitial,
                writeValue = writeValue,
                flowProvider = { neverEmits },
            )
        } else {
            KSafeComposeStateProvider(
                explicitKey = "draft",
                defaultValue = "",
                observeExternalChanges = false,
                policy = structuralEqualityPolicy(),
                instanceKey = null,
                modeKey = null,
                readInitial = readInitial,
                readDurable = { _, _ -> durable },
                writeValue = writeValue,
                flowProvider = { neverEmits },
            )
        }

        val recomposer = Recomposer(EmptyCoroutineContext)
        val composition = Composition(NoOpApplier(), recomposer)
        lateinit var state: KSafeComposeState<String>
        composition.setContent { state = provider.provideDelegate(null, ::draftProperty) }
        assertEquals("A", state.value, "sanity: the state starts in sync with the stored value")

        state.value = ""
        assertEquals("", durable, "sanity: clearing the value must reach the store")

        state.value = "B"
        notifyFailure!!(IllegalStateException("KSafe: async persist failed (test)"))

        return state to {
            composition.dispose()
            recomposer.cancel()
        }
    }
}

/** Delegate target; every test passes an explicit key, so the property name is never used. */
private var probeProperty: Double = 0.0

/** Delegate target for the faked-store test, which is typed on String. */
private var draftProperty: String = ""
