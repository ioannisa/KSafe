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
 * Tests for [KSafeComposeState] class.
 *
 * These tests verify the behavior of the Compose state wrapper.
 */
class KSafeComposeStateTest {

    // ============ INITIAL VALUE TESTS ============

    /** Verifies initial String value is correctly stored and accessible */
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

    /** Verifies initial Int value works correctly */
    @Test
    fun composeState_initialValue_intType() {
        val state = KSafeComposeState(
            initialValue = 42,
            valueSaver = { },
            policy = structuralEqualityPolicy()
        )

        assertEquals(42, state.value)
    }

    /** Verifies initial Boolean value works correctly */
    @Test
    fun composeState_initialValue_booleanType() {
        val state = KSafeComposeState(
            initialValue = true,
            valueSaver = { },
            policy = structuralEqualityPolicy()
        )

        assertTrue(state.value)
    }

    /** Verifies nullable types can be initialized with null */
    @Test
    fun composeState_initialValue_nullableType() {
        val state = KSafeComposeState<String?>(
            initialValue = null,
            valueSaver = { },
            policy = structuralEqualityPolicy()
        )

        assertEquals(null, state.value)
    }

    // ============ VALUE CHANGE TESTS ============

    /** Verifies value property setter updates state correctly */
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

    /** Verifies valueSaver callback is invoked when value changes */
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

    /** Verifies saver is not called when setting structurally equal value */
    @Test
    fun composeState_sameValue_doesNotTriggerSaver() {
        var saveCount = 0
        val state = KSafeComposeState(
            initialValue = "Same",
            valueSaver = { saveCount++ },
            policy = structuralEqualityPolicy()
        )

        state.value = "Same" // Same value

        assertEquals(0, saveCount, "Saver should not be called for equivalent values")
    }

    /** Verifies multiple sequential changes all trigger saver in order */
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

    // ============ SNAPSHOT MUTATION POLICY TESTS ============

    /** Verifies structuralEqualityPolicy skips save for equivalent data class instances */
    @Test
    fun composeState_structuralEquality_equivalentObjectsNotSaved() {
        var saveCount = 0
        data class User(val name: String)

        val state = KSafeComposeState(
            initialValue = User("Alice"),
            valueSaver = { saveCount++ },
            policy = structuralEqualityPolicy()
        )

        // Different instance but structurally equal
        state.value = User("Alice")

        assertEquals(0, saveCount, "Structurally equal objects should not trigger save")
    }

    /** Verifies structuralEqualityPolicy triggers save for different values */
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

    /** Verifies referentialEqualityPolicy triggers save for different instances */
    @Test
    fun composeState_referentialEquality_differentInstancesTriggerSave() {
        var saveCount = 0
        data class User(val name: String)

        val state = KSafeComposeState(
            initialValue = User("Alice"),
            valueSaver = { saveCount++ },
            policy = referentialEqualityPolicy()
        )

        // Different instance (even if structurally equal)
        state.value = User("Alice")

        assertEquals(1, saveCount, "Referentially different objects should trigger save")
    }

    /** Verifies neverEqualPolicy always triggers save even for same value */
    @Test
    fun composeState_neverEqualPolicy_alwaysTriggersSave() {
        var saveCount = 0
        val state = KSafeComposeState(
            initialValue = "Value",
            valueSaver = { saveCount++ },
            policy = neverEqualPolicy()
        )

        state.value = "Value" // Same value but policy says never equal

        assertEquals(1, saveCount, "Never equal policy should always trigger save")
    }

    // ============ PROPERTY DELEGATION TESTS ============

    /** Verifies getValue operator returns current state value */
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

    /** Verifies setValue operator updates state and triggers saver */
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

    // Dummy property for delegation tests
    private val dummyProperty: Int = 0

    // ============ DESTRUCTURING TESTS ============

    /** Verifies component1 destructuring returns current value */
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

    /** Verifies component2 destructuring returns functional setter */
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

    /** Verifies full destructuring pattern: val (value, setValue) = state */
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

    // ============ EDGE CASES ============

    /** Verifies transition from null to non-null triggers save */
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

    /** Verifies transition from non-null to null triggers save */
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

    /** Verifies empty string is handled as valid distinct value */
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

    /** Verifies list content changes are detected and trigger save */
    @Test
    fun composeState_listType_changesDetected() {
        var saveCount = 0
        val state = KSafeComposeState(
            initialValue = listOf(1, 2, 3),
            valueSaver = { saveCount++ },
            policy = structuralEqualityPolicy()
        )

        state.value = listOf(1, 2, 3, 4) // Different list

        assertEquals(1, saveCount)
        assertEquals(listOf(1, 2, 3, 4), state.value)
    }

    /** Verifies identical list content (different instance) doesn't trigger save */
    @Test
    fun composeState_listType_sameContentNotSaved() {
        var saveCount = 0
        val state = KSafeComposeState(
            initialValue = listOf(1, 2, 3),
            valueSaver = { saveCount++ },
            policy = structuralEqualityPolicy()
        )

        state.value = listOf(1, 2, 3) // Same content, different instance

        assertEquals(0, saveCount, "Same list content should not trigger save")
    }

    // ============ SAVER EXCEPTION HANDLING ============

    /** Verifies state updates even when saver throws exception */
    @Test
    fun composeState_saverException_stateStillUpdates() {
        val state = KSafeComposeState(
            initialValue = "Initial",
            valueSaver = { throw RuntimeException("Save failed") },
            policy = structuralEqualityPolicy()
        )

        // Should not throw, state should still update
        try {
            state.value = "New"
        } catch (e: Exception) {
            // Expected - saver throws
        }

        // Even if saver fails, state should be updated
        assertEquals("New", state.value)
    }
}
