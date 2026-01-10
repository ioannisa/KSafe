package eu.anifantakis.ksafe.compose

import androidx.compose.runtime.structuralEqualityPolicy
import androidx.compose.runtime.referentialEqualityPolicy
import androidx.compose.runtime.neverEqualPolicy
import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * Tests for [KSafe.mutableStateOf] extension function.
 *
 * These tests verify the actual integration between KSafe persistence
 * and Compose MutableState. Platform-specific implementations extend
 * this class to provide actual KSafe instances.
 */
abstract class KSafeMutableStateOfTest {

    abstract fun createKSafe(fileName: String? = null): KSafe

    // ============ BASIC MUTABLE STATE OF TESTS ============

    /** Verifies mutableStateOf returns default value when key doesn't exist */
    @Test
    fun mutableStateOf_returnsDefaultValue_whenKeyNotExists() {
        val ksafe = createKSafe()

        // Use provideDelegate manually to get the state
        val provider = ksafe.mutableStateOf("DefaultValue")
        val delegate = provider.provideDelegate(null, ::testProperty)

        val value = delegate.getValue(null, ::testProperty)
        assertEquals("DefaultValue", value)
    }

    /** Verifies mutableStateOf persists value changes to KSafe */
    @Test
    fun mutableStateOf_persistsValueChanges() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("Initial", key = "persist_test")
        val delegate = provider.provideDelegate(null, ::testProperty)

        // Change the value
        delegate.setValue(null, ::testProperty, "Changed")

        // Verify using getDirect
        val persisted = ksafe.getDirect("persist_test", "fallback", encrypted = true)
        assertEquals("Changed", persisted)
    }

    /** Verifies mutableStateOf uses property name as key when no key specified */
    @Test
    fun mutableStateOf_usesPropertyNameAsKey() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("TestValue")
        val delegate = provider.provideDelegate(null, ::myCustomProperty)

        delegate.setValue(null, ::myCustomProperty, "UpdatedValue")

        // Should be stored under "myCustomProperty" key
        val persisted = ksafe.getDirect("myCustomProperty", "fallback", encrypted = true)
        assertEquals("UpdatedValue", persisted)
    }

    /** Verifies mutableStateOf uses explicit key when specified */
    @Test
    fun mutableStateOf_usesExplicitKey() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("TestValue", key = "explicit_key")
        val delegate = provider.provideDelegate(null, ::testProperty)

        delegate.setValue(null, ::testProperty, "NewValue")

        // Should be stored under "explicit_key", not property name
        val persisted = ksafe.getDirect("explicit_key", "fallback", encrypted = true)
        assertEquals("NewValue", persisted)
    }

    // ============ ENCRYPTION TESTS ============

    /** Verifies mutableStateOf encrypts by default */
    @Test
    fun mutableStateOf_encryptsByDefault() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("SecretValue", key = "encrypted_key")
        val delegate = provider.provideDelegate(null, ::testProperty)

        delegate.setValue(null, ::testProperty, "SecretData")

        // Should be stored encrypted
        val encrypted = ksafe.getDirect("encrypted_key", "fallback", encrypted = true)
        assertEquals("SecretData", encrypted)

        // Reading unencrypted should return default (data is encrypted)
        val unencrypted = ksafe.getDirect("encrypted_key", "fallback", encrypted = false)
        assertNotEquals("SecretData", unencrypted)
    }

    /** Verifies mutableStateOf can store unencrypted when specified */
    @Test
    fun mutableStateOf_canStoreUnencrypted() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("PlainValue", key = "plain_key", encrypted = false)
        val delegate = provider.provideDelegate(null, ::testProperty)

        delegate.setValue(null, ::testProperty, "PlainData")

        // Should be readable as unencrypted
        val plain = ksafe.getDirect("plain_key", "fallback", encrypted = false)
        assertEquals("PlainData", plain)
    }

    // ============ TYPE TESTS ============

    /** Verifies mutableStateOf works with Int type */
    @Test
    fun mutableStateOf_intType() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(0, key = "int_key")
        val delegate = provider.provideDelegate(null, ::intProperty)

        delegate.setValue(null, ::intProperty, 42)

        val persisted = ksafe.getDirect("int_key", 0, encrypted = true)
        assertEquals(42, persisted)
    }

    /** Verifies mutableStateOf works with Boolean type */
    @Test
    open fun mutableStateOf_booleanType() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(false, key = "bool_key")
        val delegate = provider.provideDelegate(null, ::boolProperty)

        delegate.setValue(null, ::boolProperty, true)

        val persisted = ksafe.getDirect("bool_key", false, encrypted = true)
        assertEquals(true, persisted)
    }

    /** Verifies mutableStateOf works with Double type */
    @Test
    fun mutableStateOf_doubleType() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(0.0, key = "double_key")
        val delegate = provider.provideDelegate(null, ::doubleProperty)

        delegate.setValue(null, ::doubleProperty, 3.14159)

        val persisted = ksafe.getDirect("double_key", 0.0, encrypted = true)
        assertEquals(3.14159, persisted)
    }

    /** Verifies mutableStateOf works with Long type */
    @Test
    fun mutableStateOf_longType() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(0L, key = "long_key")
        val delegate = provider.provideDelegate(null, ::longProperty)

        delegate.setValue(null, ::longProperty, 9876543210L)

        val persisted = ksafe.getDirect("long_key", 0L, encrypted = true)
        assertEquals(9876543210L, persisted)
    }

    // ============ PERSISTENCE ACROSS INSTANCES ============

    /**
     * Verifies value persists when creating new KSafe with same fileName.
     *
     * Note: This test is open because JVM DataStore doesn't support multiple
     * instances accessing the same file. JVM implementation overrides this
     * to skip the test.
     */
    @Test
    open fun mutableStateOf_persistsAcrossInstances() {
        val ksafe1 = createKSafe("shared")

        val provider1 = ksafe1.mutableStateOf("Initial", key = "shared_key")
        val delegate1 = provider1.provideDelegate(null, ::testProperty)
        delegate1.setValue(null, ::testProperty, "Persisted")

        // Create new KSafe instance with same file
        val ksafe2 = createKSafe("shared")

        val provider2 = ksafe2.mutableStateOf("Default", key = "shared_key")
        val delegate2 = provider2.provideDelegate(null, ::testProperty)

        val value = delegate2.getValue(null, ::testProperty)
        assertEquals("Persisted", value)
    }

    // ============ POLICY TESTS ============

    /** Verifies structuralEqualityPolicy prevents save for equal values */
    @Test
    fun mutableStateOf_structuralEquality_skipsEqualValues() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(
            listOf(1, 2, 3),
            key = "list_structural",
            policy = structuralEqualityPolicy()
        )
        val delegate = provider.provideDelegate(null, ::listProperty)

        // Set initial value
        delegate.setValue(null, ::listProperty, listOf(1, 2, 3))

        // Set same content (different instance) - should not trigger save due to structural equality
        delegate.setValue(null, ::listProperty, listOf(1, 2, 3))

        val value = delegate.getValue(null, ::listProperty)
        assertEquals(listOf(1, 2, 3), value)
    }

    // ============ STATE BEHAVIOR TESTS ============

    /** Verifies getValue returns current state value */
    @Test
    fun mutableStateOf_getValue_returnsCurrentValue() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("Start", key = "get_test")
        val delegate = provider.provideDelegate(null, ::testProperty)

        assertEquals("Start", delegate.getValue(null, ::testProperty))

        delegate.setValue(null, ::testProperty, "Middle")
        assertEquals("Middle", delegate.getValue(null, ::testProperty))

        delegate.setValue(null, ::testProperty, "End")
        assertEquals("End", delegate.getValue(null, ::testProperty))
    }

    /** Verifies multiple setValue calls update state correctly */
    @Test
    fun mutableStateOf_multipleSetValue_updatesState() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(0, key = "counter")
        val delegate = provider.provideDelegate(null, ::intProperty)

        delegate.setValue(null, ::intProperty, 1)
        delegate.setValue(null, ::intProperty, 2)
        delegate.setValue(null, ::intProperty, 3)

        assertEquals(3, delegate.getValue(null, ::intProperty))
        assertEquals(3, ksafe.getDirect("counter", 0, encrypted = true))
    }

    // Dummy properties for delegation tests
    private val testProperty: String = ""
    private val myCustomProperty: String = ""
    private val intProperty: Int = 0
    private val boolProperty: Boolean = false
    private val doubleProperty: Double = 0.0
    private val longProperty: Long = 0L
    private val listProperty: List<Int> = emptyList()
}
