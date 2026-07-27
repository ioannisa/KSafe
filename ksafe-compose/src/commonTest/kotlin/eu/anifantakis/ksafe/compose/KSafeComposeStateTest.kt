package eu.anifantakis.ksafe.compose

import androidx.compose.runtime.SnapshotMutationPolicy
import androidx.compose.runtime.neverEqualPolicy
import androidx.compose.runtime.referentialEqualityPolicy
import androidx.compose.runtime.structuralEqualityPolicy
import eu.anifantakis.lib.ksafe.compose.KSafeComposeState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: KSafeComposeState value get/set, saver invocation gated by the SnapshotMutationPolicy, delegation, and destructuring.
 */
class KSafeComposeStateTest {

    @Test
    fun composeState_initialValue_isCorrect() {
        var savedValue: String? = null
        val state = KSafeComposeState(
            initialValue = "Hello",
            valueSaver = { savedValue = it },
            policy = structuralEqualityPolicy()
        )

        assertEquals("Hello", state.value)
    }

    @Test
    fun composeState_initialValue_intType() {
        val state = KSafeComposeState(
            initialValue = 42,
            valueSaver = { },
            policy = structuralEqualityPolicy()
        )

        assertEquals(42, state.value)
    }

    @Test
    fun composeState_initialValue_booleanType() {
        val state = KSafeComposeState(
            initialValue = true,
            valueSaver = { },
            policy = structuralEqualityPolicy()
        )

        assertTrue(state.value)
    }

    @Test
    fun composeState_initialValue_nullableType() {
        val state = KSafeComposeState<String?>(
            initialValue = null,
            valueSaver = { },
            policy = structuralEqualityPolicy()
        )

        assertEquals(null, state.value)
    }

    @Test
    fun composeState_valueChange_updatesState() {
        val state = KSafeComposeState(
            initialValue = "Initial",
            valueSaver = { },
            policy = structuralEqualityPolicy()
        )

        state.value = "Changed"

        assertEquals("Changed", state.value)
    }

    @Test
    fun composeState_valueChange_triggersSaver() {
        var savedValue: String? = null
        val state = KSafeComposeState(
            initialValue = "Initial",
            valueSaver = { savedValue = it },
            policy = structuralEqualityPolicy()
        )

        state.value = "NewValue"

        assertEquals("NewValue", savedValue)
    }

    @Test
    fun composeState_sameValue_doesNotTriggerSaver() {
        var saveCount = 0
        val state = KSafeComposeState(
            initialValue = "Same",
            valueSaver = { saveCount++ },
            policy = structuralEqualityPolicy()
        )

        state.value = "Same"

        assertEquals(0, saveCount, "Saver should not be called for equivalent values")
    }

    @Test
    fun composeState_multipleChanges_allSaved() {
        val savedValues = mutableListOf<Int>()
        val state = KSafeComposeState(
            initialValue = 0,
            valueSaver = { savedValues.add(it) },
            policy = structuralEqualityPolicy()
        )

        state.value = 1
        state.value = 2
        state.value = 3

        assertEquals(listOf(1, 2, 3), savedValues)
    }

    @Test
    fun composeState_structuralEquality_equivalentObjectsNotSaved() {
        var saveCount = 0
        data class User(val name: String)

        val state = KSafeComposeState(
            initialValue = User("Alice"),
            valueSaver = { saveCount++ },
            policy = structuralEqualityPolicy()
        )

        state.value = User("Alice")

        assertEquals(0, saveCount, "Structurally equal objects should not trigger save")
    }

    @Test
    fun composeState_structuralEquality_differentObjectsSaved() {
        var saveCount = 0
        data class User(val name: String)

        val state = KSafeComposeState(
            initialValue = User("Alice"),
            valueSaver = { saveCount++ },
            policy = structuralEqualityPolicy()
        )

        state.value = User("Bob")

        assertEquals(1, saveCount, "Different objects should trigger save")
    }

    @Test
    fun composeState_referentialEquality_differentInstancesTriggerSave() {
        var saveCount = 0
        data class User(val name: String)

        val state = KSafeComposeState(
            initialValue = User("Alice"),
            valueSaver = { saveCount++ },
            policy = referentialEqualityPolicy()
        )

        state.value = User("Alice")

        assertEquals(1, saveCount, "Referentially different objects should trigger save")
    }

    @Test
    fun composeState_neverEqualPolicy_alwaysTriggersSave() {
        var saveCount = 0
        val state = KSafeComposeState(
            initialValue = "Value",
            valueSaver = { saveCount++ },
            policy = neverEqualPolicy()
        )

        state.value = "Value"

        assertEquals(1, saveCount, "Never equal policy should always trigger save")
    }

    @Test
    fun composeState_getValue_returnsCurrentValue() {
        val state = KSafeComposeState(
            initialValue = 100,
            valueSaver = { },
            policy = structuralEqualityPolicy()
        )

        val value = state.getValue(null, ::dummyProperty)

        assertEquals(100, value)
    }

    @Test
    fun composeState_setValue_updatesAndSaves() {
        var savedValue: Int? = null
        val state = KSafeComposeState(
            initialValue = 0,
            valueSaver = { savedValue = it },
            policy = structuralEqualityPolicy()
        )

        state.setValue(null, ::dummyProperty, 50)

        assertEquals(50, state.value)
        assertEquals(50, savedValue)
    }

    private val dummyProperty: Int = 0

    @Test
    fun composeState_component1_returnsValue() {
        val state = KSafeComposeState(
            initialValue = "Test",
            valueSaver = { },
            policy = structuralEqualityPolicy()
        )

        val (value) = state

        assertEquals("Test", value)
    }

    @Test
    fun composeState_component2_returnsSetter() {
        var savedValue: String? = null
        val state = KSafeComposeState(
            initialValue = "Initial",
            valueSaver = { savedValue = it },
            policy = structuralEqualityPolicy()
        )

        val (_, setValue) = state
        setValue("Updated")

        assertEquals("Updated", state.value)
        assertEquals("Updated", savedValue)
    }

    @Test
    fun composeState_destructuring_fullUsage() {
        val savedValues = mutableListOf<Int>()
        val state = KSafeComposeState(
            initialValue = 0,
            valueSaver = { savedValues.add(it) },
            policy = structuralEqualityPolicy()
        )

        val (currentValue, setNewValue) = state
        assertEquals(0, currentValue)

        setNewValue(10)
        assertEquals(10, state.value)
        assertEquals(listOf(10), savedValues)
    }

    @Test
    fun composeState_nullToNonNull_triggersSave() {
        var savedValue: String? = "not_called"
        val state = KSafeComposeState<String?>(
            initialValue = null,
            valueSaver = { savedValue = it },
            policy = structuralEqualityPolicy()
        )

        state.value = "Now has value"

        assertEquals("Now has value", savedValue)
    }

    @Test
    fun composeState_nonNullToNull_triggersSave() {
        var savedValue: String? = "not_called"
        var saveCalled = false
        val state = KSafeComposeState<String?>(
            initialValue = "Has value",
            valueSaver = {
                savedValue = it
                saveCalled = true
            },
            policy = structuralEqualityPolicy()
        )

        state.value = null

        assertTrue(saveCalled)
        assertEquals(null, savedValue)
    }

    @Test
    fun composeState_emptyString_handledCorrectly() {
        var savedValue: String? = null
        val state = KSafeComposeState(
            initialValue = "Not empty",
            valueSaver = { savedValue = it },
            policy = structuralEqualityPolicy()
        )

        state.value = ""

        assertEquals("", state.value)
        assertEquals("", savedValue)
    }

    @Test
    fun composeState_listType_changesDetected() {
        var saveCount = 0
        val state = KSafeComposeState(
            initialValue = listOf(1, 2, 3),
            valueSaver = { saveCount++ },
            policy = structuralEqualityPolicy()
        )

        state.value = listOf(1, 2, 3, 4)

        assertEquals(1, saveCount)
        assertEquals(listOf(1, 2, 3, 4), state.value)
    }

    @Test
    fun composeState_listType_sameContentNotSaved() {
        var saveCount = 0
        val state = KSafeComposeState(
            initialValue = listOf(1, 2, 3),
            valueSaver = { saveCount++ },
            policy = structuralEqualityPolicy()
        )

        state.value = listOf(1, 2, 3)

        assertEquals(0, saveCount, "Same list content should not trigger save")
    }

    @Test
    fun composeState_saverException_stateStillUpdates() {
        val state = KSafeComposeState(
            initialValue = "Initial",
            valueSaver = { throw RuntimeException("Save failed") },
            policy = structuralEqualityPolicy()
        )

        try {
            state.value = "New"
        } catch (e: Exception) {
            // Saver is expected to throw here.
        }

        assertEquals("New", state.value)
    }

    /**
     * A fire-and-forget persist that fails leaves the state showing a value that never became
     * durable: storage never changed, so no echo can arrive to correct it. The failure
     * reconcile must revert to the durable value and release the write-echo latch.
     */
    @Test
    fun composeState_reconcileAfterFailedPersist_revertsThePhantomToTheDurableValue() {
        val tokens = mutableListOf<Long>()
        lateinit var state: KSafeComposeState<String>
        state = KSafeComposeState(
            initialValue = "A",
            valueSaver = { tokens += state.writeTokenInFlight() },
            policy = structuralEqualityPolicy()
        )

        state.value = "B" // optimistic write whose persist fails
        assertEquals("B", state.value)

        state.reconcileAfterFailedPersist(tokens.last(), durableValue = "A")

        assertEquals("A", state.value, "a failed persist must revert the state to the durable value")

        // The latch must have been released: external emissions reflect again.
        state.updateFromFlow("external")
        assertEquals("external", state.value, "external changes must keep reflecting after the reconcile")
    }

    /** A newer user write owns the state; a stale failure of an older write must not clobber it. */
    @Test
    fun composeState_reconcileAfterFailedPersist_isANoOp_whenANewerWriteOwnsTheState() {
        val tokens = mutableListOf<Long>()
        lateinit var state: KSafeComposeState<String>
        state = KSafeComposeState(
            initialValue = "A",
            valueSaver = { tokens += state.writeTokenInFlight() },
            policy = structuralEqualityPolicy()
        )

        state.value = "B"
        state.value = "C" // supersedes B before B's failure lands

        state.reconcileAfterFailedPersist(tokens.first(), durableValue = "A")

        assertEquals("C", state.value, "an older write's failure must not revert a newer in-flight write")
    }

    /** Reconciling without an armed latch (write already echoed/settled) must not disturb the state. */
    @Test
    fun composeState_reconcileAfterFailedPersist_isANoOp_afterTheEchoSettledTheWrite() {
        val tokens = mutableListOf<Long>()
        lateinit var state: KSafeComposeState<String>
        state = KSafeComposeState(
            initialValue = "A",
            valueSaver = { tokens += state.writeTokenInFlight() },
            policy = structuralEqualityPolicy()
        )

        state.value = "B"
        state.updateFromFlow("B") // the write's own echo clears the latch

        state.reconcileAfterFailedPersist(tokens.last(), durableValue = "A")

        assertEquals("B", state.value, "a spurious late failure must not revert an already-settled write")
    }
}
