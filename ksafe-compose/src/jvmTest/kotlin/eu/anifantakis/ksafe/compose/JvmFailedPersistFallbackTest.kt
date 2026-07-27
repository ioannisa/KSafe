package eu.anifantakis.ksafe.compose

import androidx.compose.runtime.AbstractApplier
import androidx.compose.runtime.Composition
import androidx.compose.runtime.Recomposer
import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import eu.anifantakis.lib.ksafe.compose.KSafeComposeState
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
import eu.anifantakis.lib.ksafe.compose.rememberKSafeState
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Locks in: what each persisted-state factory reconciles to when a persist fails and the durable
 * value cannot be resolved — the one outcome where the two factories used to disagree, and now
 * agree. Both settle on the value the state last had in sync with storage. `rememberKSafeState`
 * used to publish the CALLER'S DEFAULT over data that is intact on disk — for a token, reading
 * to the app as logged out.
 *
 * The motivating case is a strict entry on a locked device: it cannot be decrypted, so a read
 * yields exactly the fallback it was given and is indistinguishable from "no value". These tests
 * drive the "no value" side of that same indistinguishability (the key is deleted before the
 * failing write), because it reaches the identical code path without needing the crypto engine
 * seam, which is internal to `:ksafe` and unreachable from this module.
 *
 * The two factories reach that outcome by different routes, which is why the pair matters.
 * `mutableStateOf` is inline and holds the store, so it re-reads storage with the last in-sync
 * value as the re-read's fallback — picking up a fresher durable value when one exists.
 * `rememberKSafeState` reads through a memoized seam that binds the caller's default as its
 * fallback and cannot be handed a different one without moving the module's binary surface, so
 * it reverts to the last in-sync value directly instead of re-reading.
 *
 * Both assertions below are therefore the same assertion, made through the two factories. They
 * stay as a pair so that a change which moves only one of them fails here.
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
}

/** Delegate target; both tests pass an explicit key, so the property name is never used. */
private var probeProperty: Double = 0.0
