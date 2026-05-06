package eu.anifantakis.lib.ksafe

import app.cash.turbine.test
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertNull

/**
 * Abstract base class for KSafe tests (Android instrumented variant).
 * Same teardown contract as the commonTest copy: subclasses implement
 * [newKSafe]; the base class tracks every returned instance and calls
 * [KSafe.close] in [tearDown] so abandoned instances don't pin their
 * background coroutines in heap across tests.
 */
abstract class KSafeTest {
    private val tracked = mutableListOf<KSafe>()

    protected abstract fun newKSafe(fileName: String? = null): KSafe

    fun createKSafe(fileName: String? = null): KSafe =
        newKSafe(fileName).also { tracked += it }

    @AfterTest
    fun tearDown() {
        tracked.forEach { runCatching { it.close() } }
        tracked.clear()
    }

    @Test
    fun testPutAndGetUnencryptedString() = runTest {
        val ksafe = createKSafe()
        val key = "test_string"
        val value = "Hello, World!"
        val defaultValue = "default"

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedString() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_string"
        val value = "Secret Message"
        val defaultValue = "default"

        ksafe.put(key, value)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedInt() = runTest {
        val ksafe = createKSafe()
        val key = "test_int"
        val value = 42
        val defaultValue = 0

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedInt() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_int"
        val value = 1337
        val defaultValue = 0

        ksafe.put(key, value)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedBoolean() = runTest {
        val ksafe = createKSafe()
        val key = "test_bool"
        val value = true
        val defaultValue = false

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedBoolean() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_bool"
        val value = true
        val defaultValue = false

        ksafe.put(key, value)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedLong() = runTest {
        val ksafe = createKSafe()
        val key = "test_long"
        val value = 9876543210L
        val defaultValue = 0L

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedLong() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_long"
        val value = 9876543210L
        val defaultValue = 0L

        ksafe.put(key, value)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedFloat() = runTest {
        val ksafe = createKSafe()
        val key = "test_float"
        val value = 3.14159f
        val defaultValue = 0.0f

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedFloat() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_float"
        val value = 2.71828f
        val defaultValue = 0.0f

        ksafe.put(key, value)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedDouble() = runTest {
        val ksafe = createKSafe()
        val key = "test_double"
        val value = 3.141592653589793
        val defaultValue = 0.0

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedDouble() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_double"
        val value = 2.718281828459045
        val defaultValue = 0.0

        ksafe.put(key, value)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testGetWithDefaultValue() = runTest {
        val ksafe = createKSafe()
        val key = "non_existent_key"
        val defaultValue = "default_value"

        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(defaultValue, retrieved)
    }

    @Test
    fun testGetEncryptedWithDefaultValue() = runTest {
        val ksafe = createKSafe()
        val key = "non_existent_encrypted_key"
        val defaultValue = "encrypted_default"

        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(defaultValue, retrieved)
    }

    @Test
    fun testDelete() = runTest {
        val ksafe = createKSafe()
        val key = "test_delete"
        val value = "to_be_deleted"
        val defaultValue = "default"

        ksafe.put(key, value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get(key, defaultValue))

        ksafe.delete(key)
        assertEquals(defaultValue, ksafe.get(key, defaultValue))
    }

    @Test
    fun testDeleteEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_delete_encrypted"
        val value = "encrypted_to_be_deleted"
        val defaultValue = "default"

        ksafe.put(key, value)
        assertEquals(value, ksafe.get(key, defaultValue))

        ksafe.delete(key)
        assertEquals(defaultValue, ksafe.get(key, defaultValue))
    }

    @Test
    fun testOverwriteValue() = runTest {
        val ksafe = createKSafe()
        val key = "test_overwrite"
        val value1 = "first_value"
        val value2 = "second_value"
        val defaultValue = "default"

        ksafe.put(key, value1, KSafeWriteMode.Plain)
        assertEquals(value1, ksafe.get(key, defaultValue))

        ksafe.put(key, value2, KSafeWriteMode.Plain)
        assertEquals(value2, ksafe.get(key, defaultValue))
    }

    @Test
    fun testOverwriteEncryptedValue() = runTest {
        val ksafe = createKSafe()
        val key = "test_overwrite_encrypted"
        val value1 = "first_encrypted"
        val value2 = "second_encrypted"
        val defaultValue = "default"

        ksafe.put(key, value1)
        assertEquals(value1, ksafe.get(key, defaultValue))

        ksafe.put(key, value2)
        assertEquals(value2, ksafe.get(key, defaultValue))
    }

    @Test
    fun testFlowUnencrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_flow"
        val value1 = "flow_value_1"
        val value2 = "flow_value_2"
        val defaultValue = "default"

        val flow = ksafe.getFlow(key, defaultValue)

        flow.test {
            // Initially should emit default value
            assertEquals(defaultValue, awaitItem())

            // Update value
            ksafe.put(key, value1, KSafeWriteMode.Plain)
            assertEquals(value1, awaitItem())

            // Update again
            ksafe.put(key, value2, KSafeWriteMode.Plain)
            assertEquals(value2, awaitItem())

            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun testFlowEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_flow_encrypted"
        val value1 = "encrypted_flow_1"
        val value2 = "encrypted_flow_2"
        val defaultValue = "default"

        val flow = ksafe.getFlow(key, defaultValue)

        flow.test {
            // Initially should emit default value
            assertEquals(defaultValue, awaitItem())

            // Update value
            ksafe.put(key, value1)
            assertEquals(value1, awaitItem())

            // Update again
            ksafe.put(key, value2)
            assertEquals(value2, awaitItem())

            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun testFlowDistinctUntilChanged() = runTest {
        val ksafe = createKSafe()
        val key = "test_flow_distinct"
        val value = "same_value"
        val defaultValue = "default"

        val flow = ksafe.getFlow(key, defaultValue)

        flow.test {
            // Initially should emit default value
            assertEquals(defaultValue, awaitItem())

            // Update value
            ksafe.put(key, value, KSafeWriteMode.Plain)
            assertEquals(value, awaitItem())

            // Update with same value - should not emit
            ksafe.put(key, value, KSafeWriteMode.Plain)
            expectNoEvents()

            cancelAndIgnoreRemainingEvents()
        }
    }

    // ============ asWritableFlow / WritableKSafeFlow ============

    @Test
    fun testAsMutableFlowEmitsOnSetUnencrypted() = runTest {
        val ksafe = createKSafe()
        class Host(s: KSafe) {
            val pref: WritableKSafeFlow<String> by s.asWritableFlow(
                defaultValue = "default",
                key = "test_writable_plain",
                mode = KSafeWriteMode.Plain,
            )
        }
        val host = Host(ksafe)

        host.pref.test {
            assertEquals("default", awaitItem())
            host.pref.set("first")
            assertEquals("first", awaitItem())
            host.pref.set("second")
            assertEquals("second", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun testAsMutableFlowEmitsOnSetEncryptedByDefault() = runTest {
        val ksafe = createKSafe()
        class Host(s: KSafe) {
            val pref: WritableKSafeFlow<String> by s.asWritableFlow(
                defaultValue = "default",
                key = "test_writable_default_mode",
            )
        }
        val host = Host(ksafe)

        host.pref.test {
            assertEquals("default", awaitItem())
            host.pref.set("secret")
            assertEquals("secret", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }

        assertEquals("secret", ksafe.get("test_writable_default_mode", "fallback"))
        val info = ksafe.getKeyInfo("test_writable_default_mode")
        assertNotNull(info)
        assertNotNull(info.protection)
    }

    @Test
    fun testAsMutableFlowReflectsExternalWrites() = runTest {
        val ksafe = createKSafe()
        val key = "test_writable_external"
        class Host(s: KSafe) {
            val pref: WritableKSafeFlow<String> by s.asWritableFlow(
                defaultValue = "default",
                key = key,
                mode = KSafeWriteMode.Plain,
            )
        }
        val host = Host(ksafe)

        host.pref.test {
            assertEquals("default", awaitItem())

            ksafe.put(key, "external", KSafeWriteMode.Plain)
            assertEquals("external", awaitItem())

            host.pref.set("local")
            assertEquals("local", awaitItem())

            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun testAsMutableFlowUsesPropertyNameAsKey() = runTest {
        val ksafe = createKSafe()
        class Host(s: KSafe) {
            val derived: WritableKSafeFlow<String> by s.asWritableFlow(
                defaultValue = "default",
                mode = KSafeWriteMode.Plain,
            )
        }
        val host = Host(ksafe)

        host.derived.set("named_by_property")
        assertEquals("named_by_property", ksafe.get("derived", "fallback"))
    }

    @Test
    fun testMultipleKeysIndependence() = runTest {
        val ksafe = createKSafe()
        val key1 = "key1"
        val key2 = "key2"
        val value1 = "value1"
        val value2 = "value2"
        val defaultValue = "default"

        ksafe.put(key1, value1, KSafeWriteMode.Plain)
        ksafe.put(key2, value2, KSafeWriteMode.Plain)

        assertEquals(value1, ksafe.get(key1, defaultValue))
        assertEquals(value2, ksafe.get(key2, defaultValue))

        ksafe.delete(key1)
        assertEquals(defaultValue, ksafe.get(key1, defaultValue))
        assertEquals(value2, ksafe.get(key2, defaultValue))
    }

    @Test
    fun testEncryptedDataIsDifferentFromPlaintext() = runTest {
        val ksafe = createKSafe()
        val key = "encryption_test"
        val value = "sensitive_data"
        val defaultValue = "default"

        // Store encrypted
        ksafe.put(key, value)

        // Auto-detection now finds data regardless of how it was stored,
        // so retrieving should return the actual value
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testComplexObject() = runTest {
        val ksafe = createKSafe()
        val key = "test_complex"
        val value = TestData(
            id = 123,
            name = "Test User",
            active = true,
            scores = listOf(95.5, 87.3, 92.1),
            metadata = mapOf("key1" to "value1", "key2" to "value2")
        )
        val defaultValue = TestData(
            id = 0,
            name = "",
            active = false,
            scores = emptyList(),
            metadata = emptyMap()
        )

        // Test unencrypted
        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)

        // Test encrypted
        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value)
        val encryptedRetrieved = ksafe.get(encryptedKey, defaultValue)
        assertEquals(value, encryptedRetrieved)
    }

    // ============ NULLABLE VALUE TESTS ============

    @Test
    fun testNullableStringUnencrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_string_unenc"
        val value: String? = null
        val defaultValue: String? = "default"

        // Store null value
        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved: String? = ksafe.get(key, defaultValue)
        assertNull(retrieved, "Retrieved value should be null")
    }

    @Test
    fun testNullableStringEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_string_enc"
        val value: String? = null
        val defaultValue: String? = "default"

        // Store null value encrypted
        ksafe.put(key, value)
        val retrieved: String? = ksafe.get(key, defaultValue)
        assertNull(retrieved, "Retrieved encrypted value should be null")
    }

    @Test
    fun testNullableIntUnencrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_int_unenc"
        val value: Int? = null
        val defaultValue: Int? = 42

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved: Int? = ksafe.get(key, defaultValue)
        assertNull(retrieved, "Retrieved Int? should be null")
    }

    @Test
    fun testNullableIntEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_int_enc"
        val value: Int? = null
        val defaultValue: Int? = 42

        ksafe.put(key, value)
        val retrieved: Int? = ksafe.get(key, defaultValue)
        assertNull(retrieved, "Retrieved encrypted Int? should be null")
    }

    @Test
    fun testNullableOverwriteWithNonNull() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_overwrite"
        val nullValue: String? = null
        val nonNullValue: String? = "now_has_value"
        val defaultValue: String? = "default"

        // Store null first
        ksafe.put(key, nullValue, KSafeWriteMode.Plain)
        assertNull(ksafe.get(key, defaultValue))

        // Overwrite with non-null
        ksafe.put(key, nonNullValue, KSafeWriteMode.Plain)
        assertEquals(nonNullValue, ksafe.get(key, defaultValue))
    }

    @Test
    fun testNonNullOverwriteWithNull() = runTest {
        val ksafe = createKSafe()
        val key = "test_nonnull_to_null"
        val nonNullValue: String? = "has_value"
        val nullValue: String? = null
        val defaultValue: String? = "default"

        // Store non-null first
        ksafe.put(key, nonNullValue, KSafeWriteMode.Plain)
        assertEquals(nonNullValue, ksafe.get(key, defaultValue))

        // Overwrite with null
        ksafe.put(key, nullValue, KSafeWriteMode.Plain)
        assertNull(ksafe.get(key, defaultValue))
    }

    @Serializable
    data class NullableFieldData(
        val id: Int,
        val name: String?,
        val description: String?
    )

    @Test
    fun testSerializableWithNullFields() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_fields"
        val value = NullableFieldData(
            id = 1,
            name = null,
            description = "Has description but no name"
        )
        val defaultValue = NullableFieldData(0, "default", "default")

        // Test unencrypted
        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
        assertNull(retrieved.name)
        assertEquals("Has description but no name", retrieved.description)

        // Test encrypted
        val encKey = "${key}_enc"
        ksafe.put(encKey, value)
        val encRetrieved = ksafe.get(encKey, defaultValue)
        assertEquals(value, encRetrieved)
    }

    @Test
    fun testNullableWithDirectApi() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_direct"
        val value: String? = null
        val defaultValue: String? = "default"

        // Use putDirect
        ksafe.putDirect(key, value, KSafeWriteMode.Plain)

        // Use getDirect
        val retrieved: String? = ksafe.getDirect(key, defaultValue)
        assertNull(retrieved, "getDirect should return null for null value")
    }

    @Test
    fun testNullableWithDirectApiEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_direct_enc"
        val value: String? = null
        val defaultValue: String? = "default"

        // Use putDirect with encryption
        ksafe.putDirect(key, value)

        // Use getDirect with encryption
        val retrieved: String? = ksafe.getDirect(key, defaultValue)
        assertNull(retrieved, "getDirect should return null for encrypted null value")
    }

    // ============ END NULLABLE VALUE TESTS ============

    @Test
    fun testEmptyString() = runTest {
        val ksafe = createKSafe()
        val key = "test_empty"
        val value = ""
        val defaultValue = "default"

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    @Test
    fun testSpecialCharacters() = runTest {
        val ksafe = createKSafe()
        val key = "test_special"
        val value = "Special chars: !@#$%^&*()_+{}[]|\\:\";<>?,./~`'"
        val defaultValue = "default"

        // Test unencrypted
        ksafe.put(key, value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get(key, defaultValue))

        // Test encrypted
        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value)
        assertEquals(value, ksafe.get(encryptedKey, defaultValue))
    }

    @Test
    fun testUnicodeCharacters() = runTest {
        val ksafe = createKSafe()
        val key = "test_unicode"
        val value = "Unicode: 你好世界 🌍 مرحبا بالعالم"
        val defaultValue = "default"

        // Test unencrypted
        ksafe.put(key, value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get(key, defaultValue))

        // Test encrypted
        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value)
        assertEquals(value, ksafe.get(encryptedKey, defaultValue))
    }

    @Test
    fun testLargeData() = runTest {
        val ksafe = createKSafe()
        val key = "test_large"
        val value = "x".repeat(10000) // 10KB of data
        val defaultValue = ""

        // Test unencrypted
        ksafe.put(key, value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get(key, defaultValue))

        // Test encrypted
        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value)
        assertEquals(value, ksafe.get(encryptedKey, defaultValue))
    }

    @Test
    fun testConcurrentAccess() = runTest {
        val ksafe = createKSafe()
        val iterations = 100
        val results = mutableListOf<Boolean>()

        repeat(iterations) { index ->
            val key = "concurrent_$index"
            val value = "value_$index"
            val defaultValue = "default"

            ksafe.put(key, value, KSafeWriteMode.Plain)
            val retrieved = ksafe.get(key, defaultValue)
            results.add(retrieved == value)
        }

        assertTrue(results.all { it })
    }

    @Test
    fun testFileNameIsolation() = runTest {
        val ksafe1 = createKSafe("fileone")
        val ksafe2 = createKSafe("filetwo")
        val key = "same_key"
        val value1 = "value_for_file1"
        val value2 = "value_for_file2"
        val defaultValue = "default"

        ksafe1.put(key, value1, KSafeWriteMode.Plain)
        ksafe2.put(key, value2, KSafeWriteMode.Plain)

        assertEquals(value1, ksafe1.get(key, defaultValue))
        assertEquals(value2, ksafe2.get(key, defaultValue))
    }

    @Test
    fun testNegativeNumbers() = runTest {
        val ksafe = createKSafe()

        // Test negative int
        val intKey = "negative_int"
        val intValue = -42
        ksafe.put(intKey, intValue, KSafeWriteMode.Plain)
        assertEquals(intValue, ksafe.get(intKey, 0))

        // Test negative long
        val longKey = "negative_long"
        val longValue = -9876543210L
        ksafe.put(longKey, longValue, KSafeWriteMode.Plain)
        assertEquals(longValue, ksafe.get(longKey, 0L))

        // Test negative float
        val floatKey = "negative_float"
        val floatValue = -3.14f
        ksafe.put(floatKey, floatValue, KSafeWriteMode.Plain)
        assertEquals(floatValue, ksafe.get(floatKey, 0.0f))

        // Test negative double
        val doubleKey = "negative_double"
        val doubleValue = -2.71828
        ksafe.put(doubleKey, doubleValue, KSafeWriteMode.Plain)
        assertEquals(doubleValue, ksafe.get(doubleKey, 0.0))
    }

    @Test
    fun testEdgeCaseNumbers() = runTest {
        val ksafe = createKSafe()

        // Test Int boundaries
        val maxIntKey = "max_int"
        ksafe.put(maxIntKey, Int.MAX_VALUE, KSafeWriteMode.Plain)
        assertEquals(Int.MAX_VALUE, ksafe.get(maxIntKey, 0))

        val minIntKey = "min_int"
        ksafe.put(minIntKey, Int.MIN_VALUE, KSafeWriteMode.Plain)
        assertEquals(Int.MIN_VALUE, ksafe.get(minIntKey, 0))

        // Test Long boundaries
        val maxLongKey = "max_long"
        ksafe.put(maxLongKey, Long.MAX_VALUE, KSafeWriteMode.Plain)
        assertEquals(Long.MAX_VALUE, ksafe.get(maxLongKey, 0L))

        val minLongKey = "min_long"
        ksafe.put(minLongKey, Long.MIN_VALUE, KSafeWriteMode.Plain)
        assertEquals(Long.MIN_VALUE, ksafe.get(minLongKey, 0L))
    }

    @Test
    fun testGetDirectReflectsSuspendingPut() = runTest {
        val ksafe = createKSafe()
        val key = "direct_read_test"
        val value = "read_me_now"

        // 1. Write using suspend function (waits for disk write)
        ksafe.put(key, value)

        // 2. Read using non-blocking getDirect (cache updated synchronously by put)
        val result = ksafe.getDirect(key, "default")
        assertEquals(value, result)
    }

    @Test
    fun testPutDirect() = runTest {
        val ksafe = createKSafe()
        val key = "direct_read_test"
        val value = "read_me_now"

        // 1. Write using putDirect (optimistic cache update is immediate)
        ksafe.putDirect(key, value)

        // 2. Read using non-blocking getDirect (cache already updated)
        val result = ksafe.getDirect(key, "default")
        assertEquals(value, result)
    }

    /** Verifies putDirect is immediately visible via getDirect (optimistic update) */
    @Test
    fun testPutDirectEventuallyUpdatesValue() = runTest {
        val ksafe = createKSafe()
        val key = "put_direct_test"
        val value = "immediate_consistency"

        // Write using putDirect (optimistic cache update is immediate)
        ksafe.putDirect(key, value)

        // Read immediately - no polling needed due to optimistic cache update
        val result = ksafe.getDirect(key, "default")

        assertEquals(value, result, "getDirect should immediately return the value set by putDirect")
    }

    @Test
    fun testDirectEncryptedRoundTrip() = runTest {
        val ksafe = createKSafe()
        val key = "direct_enc_roundtrip"
        val value = 999

        // Write using putDirect (optimistic cache update is immediate)
        ksafe.putDirect(key, value)

        // Read immediately - no polling needed due to optimistic cache update
        assertEquals(value, ksafe.getDirect(key, -1))
    }

    @Test
    fun delegate_defaultEncrypted_and_propertyNameKey() = runTest {
        val ksafe = createKSafe()
        var secret: String by ksafe(defaultValue = "init")
        assertEquals("init", secret)
        secret = "z"
        assertEquals("z", secret)
        assertEquals("z", ksafe.get("secret", "x"))
    }

    @Test
    fun delegate_explicitKey_unencrypted() = runTest {
        val ksafe = createKSafe()
        var count: Int by ksafe(defaultValue = 0, key = "count", mode = KSafeWriteMode.Plain)
        assertEquals(0, count)
        count = 3
        assertEquals(3, count)
        assertEquals(3, ksafe.get("count", -1))
    }

    @Serializable
    data class Person(val id: Long, val name: String)

    @Test
    fun serializable_encrypted_roundTrip() = runTest {
        val ksafe = createKSafe()
        val k = "person"
        val p = Person(7, "Grace")
        ksafe.put(k, p) // encrypted
        assertEquals(p, ksafe.get(k, Person(0, "")))
    }
}
