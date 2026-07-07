package eu.anifantakis.ksafe.compose

import androidx.compose.runtime.structuralEqualityPolicy
import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Locks in: KSafe.mutableStateOf delegate — default value, key derivation, persistence, encryption tier, supported types, and equality policy.
 */
abstract class KSafeMutableStateOfTest {

    private val tracked = mutableListOf<KSafe>()

    protected abstract fun newKSafe(fileName: String? = null): KSafe

    fun createKSafe(fileName: String? = null): KSafe =
        newKSafe(fileName).also { tracked += it }

    @AfterTest
    fun tearDown() {
        // Close tracked instances so abandoned coroutines/DataStores don't pin heap across tests.
        tracked.forEach { runCatching { it.close() } }
        tracked.clear()
    }

    @Test
    fun mutableStateOf_returnsDefaultValue_whenKeyNotExists() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("DefaultValue")
        val delegate = provider.provideDelegate(null, ::testProperty)

        val value = delegate.getValue(null, ::testProperty)
        assertEquals("DefaultValue", value)
    }

    @Test
    fun mutableStateOf_persistsValueChanges() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("Initial", key = "persist_test")
        val delegate = provider.provideDelegate(null, ::testProperty)

        delegate.setValue(null, ::testProperty, "Changed")

        val persisted = ksafe.getDirect("persist_test", "fallback", encrypted = true)
        assertEquals("Changed", persisted)
    }

    @Test
    fun mutableStateOf_usesPropertyNameAsKey() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("TestValue")
        val delegate = provider.provideDelegate(null, ::myCustomProperty)

        delegate.setValue(null, ::myCustomProperty, "UpdatedValue")

        val persisted = ksafe.getDirect("myCustomProperty", "fallback", encrypted = true)
        assertEquals("UpdatedValue", persisted)
    }

    @Test
    fun mutableStateOf_usesExplicitKey() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("TestValue", key = "explicit_key")
        val delegate = provider.provideDelegate(null, ::testProperty)

        delegate.setValue(null, ::testProperty, "NewValue")

        val persisted = ksafe.getDirect("explicit_key", "fallback", encrypted = true)
        assertEquals("NewValue", persisted)
    }

    @Test
    fun mutableStateOf_encryptsByDefault() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("SecretValue", key = "encrypted_key")
        val delegate = provider.provideDelegate(null, ::testProperty)

        delegate.setValue(null, ::testProperty, "SecretData")

        assertEquals("SecretData", ksafe.getDirect("encrypted_key", "fallback"))

        // Encryption-by-default is observable via metadata: getKeyInfo must report a non-null protection tier.
        val keyInfo = ksafe.getKeyInfo("encrypted_key")
        assertNotNull(keyInfo, "Key info should exist for stored value")
        assertNotNull(
            keyInfo.protection,
            "Default mutableStateOf write must record an encrypted protection tier",
        )
    }

    @Test
    fun mutableStateOf_canStoreUnencrypted() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf("PlainValue", key = "plain_key", encrypted = false)
        val delegate = provider.provideDelegate(null, ::testProperty)

        delegate.setValue(null, ::testProperty, "PlainData")

        assertEquals("PlainData", ksafe.getDirect("plain_key", "fallback"))

        // Plain writes record protection = null, observable via getKeyInfo.
        val keyInfo = ksafe.getKeyInfo("plain_key")
        assertNotNull(keyInfo, "Key info should exist for stored value")
        assertNull(
            keyInfo.protection,
            "Plain write must record a null protection tier (not encrypted)",
        )
    }

    @Test
    fun mutableStateOf_intType() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(0, key = "int_key")
        val delegate = provider.provideDelegate(null, ::intProperty)

        delegate.setValue(null, ::intProperty, 42)

        val persisted = ksafe.getDirect("int_key", 0, encrypted = true)
        assertEquals(42, persisted)
    }

    @Test
    open fun mutableStateOf_booleanType() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(false, key = "bool_key")
        val delegate = provider.provideDelegate(null, ::boolProperty)

        delegate.setValue(null, ::boolProperty, true)

        val persisted = ksafe.getDirect("bool_key", false, encrypted = true)
        assertEquals(true, persisted)
    }

    @Test
    fun mutableStateOf_doubleType() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(0.0, key = "double_key")
        val delegate = provider.provideDelegate(null, ::doubleProperty)

        delegate.setValue(null, ::doubleProperty, 3.14159)

        val persisted = ksafe.getDirect("double_key", 0.0, encrypted = true)
        assertEquals(3.14159, persisted)
    }

    @Test
    fun mutableStateOf_longType() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(0L, key = "long_key")
        val delegate = provider.provideDelegate(null, ::longProperty)

        delegate.setValue(null, ::longProperty, 9876543210L)

        val persisted = ksafe.getDirect("long_key", 0L, encrypted = true)
        assertEquals(9876543210L, persisted)
    }

    // open: JVM DataStore forbids multiple instances on one file, so the JVM subclass skips this.
    @Test
    open fun mutableStateOf_persistsAcrossInstances() {
        val ksafe1 = createKSafe("shared")

        val provider1 = ksafe1.mutableStateOf("Initial", key = "shared_key")
        val delegate1 = provider1.provideDelegate(null, ::testProperty)
        delegate1.setValue(null, ::testProperty, "Persisted")

        val ksafe2 = createKSafe("shared")

        val provider2 = ksafe2.mutableStateOf("Default", key = "shared_key")
        val delegate2 = provider2.provideDelegate(null, ::testProperty)

        val value = delegate2.getValue(null, ::testProperty)
        assertEquals("Persisted", value)
    }

    @Test
    fun mutableStateOf_structuralEquality_skipsEqualValues() {
        val ksafe = createKSafe()

        val provider = ksafe.mutableStateOf(
            listOf(1, 2, 3),
            key = "list_structural",
            policy = structuralEqualityPolicy()
        )
        val delegate = provider.provideDelegate(null, ::listProperty)

        delegate.setValue(null, ::listProperty, listOf(1, 2, 3))

        // Same content, different instance: structural equality skips the save.
        delegate.setValue(null, ::listProperty, listOf(1, 2, 3))

        val value = delegate.getValue(null, ::listProperty)
        assertEquals(listOf(1, 2, 3), value)
    }

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

    private val testProperty: String = ""
    private val myCustomProperty: String = ""
    private val intProperty: Int = 0
    private val boolProperty: Boolean = false
    private val doubleProperty: Double = 0.0
    private val longProperty: Long = 0L
    private val listProperty: List<Int> = emptyList()
}
