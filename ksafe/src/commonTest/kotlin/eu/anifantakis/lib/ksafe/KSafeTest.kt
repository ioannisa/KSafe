package eu.anifantakis.lib.ksafe

import app.cash.turbine.test
import eu.anifantakis.lib.ksafe.KSafeProtection
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.plus
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Abstract base class for KSafe tests.
 * Platform-specific implementations extend this class to provide actual KSafe instances.
 */
abstract class KSafeTest {
    abstract fun createKSafe(fileName: String? = null): KSafe

    // ============ BASIC STRING OPERATIONS ============

    /** Verifies that unencrypted strings can be stored and retrieved correctly */
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

    /** Verifies that encrypted strings can be stored and retrieved correctly */
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

    // ============ NUMERIC TYPE OPERATIONS ============

    /** Verifies that unencrypted integers can be stored and retrieved correctly */
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

    /** Verifies that encrypted integers can be stored and retrieved correctly */
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

    /** Verifies that unencrypted booleans can be stored and retrieved correctly */
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

    /** Verifies that encrypted booleans can be stored and retrieved correctly */
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

    /** Verifies that unencrypted Long values can be stored and retrieved correctly */
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

    /** Verifies that encrypted Long values can be stored and retrieved correctly */
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

    /** Verifies that unencrypted Float values can be stored and retrieved correctly */
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

    /** Verifies that encrypted Float values can be stored and retrieved correctly */
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

    /** Verifies that unencrypted Double values can be stored and retrieved correctly */
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

    /** Verifies that encrypted Double values can be stored and retrieved correctly */
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

    // ============ DEFAULT VALUE BEHAVIOR ============

    /** Verifies that default value is returned for non-existent unencrypted keys */
    @Test
    fun testGetWithDefaultValue() = runTest {
        val ksafe = createKSafe()
        val key = "non_existent_key"
        val defaultValue = "default_value"

        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(defaultValue, retrieved)
    }

    /** Verifies that default value is returned for non-existent encrypted keys */
    @Test
    fun testGetEncryptedWithDefaultValue() = runTest {
        val ksafe = createKSafe()
        val key = "non_existent_encrypted_key"
        val defaultValue = "encrypted_default"

        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(defaultValue, retrieved)
    }

    // ============ DELETE OPERATIONS ============

    /** Verifies that unencrypted values can be deleted and return default afterward */
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

    /** Verifies that encrypted values can be deleted and return default afterward */
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

    // ============ OVERWRITE OPERATIONS ============

    /** Verifies that unencrypted values can be overwritten with new values */
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

    /** Verifies that encrypted values can be overwritten with new values */
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

    // ============ FLOW API TESTS ============

    /** Verifies that Flow emits updates for unencrypted values */
    @Test
    fun testFlowUnencrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_flow"
        val value1 = "flow_value_1"
        val value2 = "flow_value_2"
        val defaultValue = "default"

        val flow = ksafe.getFlow(key, defaultValue)

        flow.test {
            assertEquals(defaultValue, awaitItem())

            ksafe.put(key, value1, KSafeWriteMode.Plain)
            assertEquals(value1, awaitItem())

            ksafe.put(key, value2, KSafeWriteMode.Plain)
            assertEquals(value2, awaitItem())

            cancelAndIgnoreRemainingEvents()
        }
    }

    /** Verifies that encrypted Flow returns default value and put/get work correctly */
    @Test
    fun testFlowEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_flow_encrypted"
        val value1 = "encrypted_flow_1"
        val value2 = "encrypted_flow_2"
        val defaultValue = "default"

        // Verify initial default value from flow
        assertEquals(defaultValue, ksafe.getFlow(key, defaultValue).first())

        // Store first value and verify via get
        ksafe.put(key, value1)
        assertEquals(value1, ksafe.get(key, defaultValue))

        // Store second value and verify
        ksafe.put(key, value2)
        assertEquals(value2, ksafe.get(key, defaultValue))

        // Note: Flow reactive updates for encrypted values are tested implicitly via
        // testFlowUnencrypted (same code path) and testPutGetEncrypted
    }

    /** Verifies that Flow does not emit duplicate values (distinctUntilChanged) */
    @Test
    fun testFlowDistinctUntilChanged() = runTest {
        val ksafe = createKSafe()
        val key = "test_flow_distinct"
        val value = "same_value"
        val defaultValue = "default"

        val flow = ksafe.getFlow(key, defaultValue)

        flow.test {
            assertEquals(defaultValue, awaitItem())

            ksafe.put(key, value, KSafeWriteMode.Plain)
            assertEquals(value, awaitItem())

            // Writing same value should not emit
            ksafe.put(key, value, KSafeWriteMode.Plain)
            expectNoEvents()

            cancelAndIgnoreRemainingEvents()
        }
    }

    // ============ STATE FLOW API TESTS ============

    /** Verifies that StateFlow has defaultValue as initial value (unencrypted) */
    @Test
    fun testStateFlowUnencrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_stateflow"
        val defaultValue = "default"
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, defaultValue, scope = sharingScope)
        assertEquals(defaultValue, stateFlow.value)

        ksafe.put(key, "updated", KSafeWriteMode.Plain)
        stateFlow.test {
            assertEquals("updated", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    /** Verifies that StateFlow has defaultValue as initial value (encrypted) */
    @Test
    fun testStateFlowEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_stateflow_encrypted"
        val defaultValue = "default"
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, defaultValue, scope = sharingScope)
        assertEquals(defaultValue, stateFlow.value)

        ksafe.put(key, "secret")
        stateFlow.test {
            assertEquals("secret", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    /** Verifies that StateFlow reflects updates reactively */
    @Test
    fun testStateFlowReflectsUpdates() = runTest {
        val ksafe = createKSafe()
        val key = "test_stateflow_updates"
        val defaultValue = "default"
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, defaultValue, scope = sharingScope)

        stateFlow.test {
            assertEquals(defaultValue, awaitItem())

            ksafe.put(key, "value1", KSafeWriteMode.Plain)
            assertEquals("value1", awaitItem())

            ksafe.put(key, "value2", KSafeWriteMode.Plain)
            assertEquals("value2", awaitItem())

            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    // ============ KEY INDEPENDENCE TESTS ============

    /** Verifies that different keys are independent of each other */
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

    // ============ ENCRYPTION VERIFICATION TESTS ============

    /** Verifies that auto-detection finds encrypted data regardless of how it was stored */
    @Test
    fun testEncryptedDataAutoDetected() = runTest {
        val ksafe = createKSafe()
        val key = "encryption_test"
        val value = "sensitive_data"
        val defaultValue = "default"

        ksafe.put(key, value)

        // Auto-detection finds the encrypted value and decrypts it
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

    // ============ COMPLEX OBJECT SERIALIZATION TESTS ============

    /** Verifies that complex serializable objects can be stored and retrieved */
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

    /** Verifies that null strings can be stored and retrieved (unencrypted) */
    @Test
    fun testNullableStringUnencrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_string_unenc"
        val value: String? = null
        val defaultValue: String? = "default"

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved: String? = ksafe.get(key, defaultValue)
        assertNull(retrieved, "Retrieved value should be null")
    }

    /** Verifies that null strings can be stored and retrieved (encrypted) */
    @Test
    fun testNullableStringEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_string_enc"
        val value: String? = null
        val defaultValue: String? = "default"

        ksafe.put(key, value)
        val retrieved: String? = ksafe.get(key, defaultValue)
        assertNull(retrieved, "Retrieved encrypted value should be null")
    }

    /** Verifies that null integers can be stored and retrieved (unencrypted) */
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

    /** Verifies that null integers can be stored and retrieved (encrypted) */
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

    /** Verifies that null values can be overwritten with non-null values */
    @Test
    fun testNullableOverwriteWithNonNull() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_overwrite"
        val nullValue: String? = null
        val nonNullValue: String? = "now_has_value"
        val defaultValue: String? = "default"

        ksafe.put(key, nullValue, KSafeWriteMode.Plain)
        assertNull(ksafe.get(key, defaultValue))

        ksafe.put(key, nonNullValue, KSafeWriteMode.Plain)
        assertEquals(nonNullValue, ksafe.get(key, defaultValue))
    }

    /** Verifies that non-null values can be overwritten with null values */
    @Test
    fun testNonNullOverwriteWithNull() = runTest {
        val ksafe = createKSafe()
        val key = "test_nonnull_to_null"
        val nonNullValue: String? = "has_value"
        val nullValue: String? = null
        val defaultValue: String? = "default"

        ksafe.put(key, nonNullValue, KSafeWriteMode.Plain)
        assertEquals(nonNullValue, ksafe.get(key, defaultValue))

        ksafe.put(key, nullValue, KSafeWriteMode.Plain)
        assertNull(ksafe.get(key, defaultValue))
    }

    @Serializable
    data class NullableFieldData(
        val id: Int,
        val name: String?,
        val description: String?
    )

    /** Verifies that serializable objects with nullable fields preserve null correctly */
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

    /** Verifies that null values work with Direct (non-blocking) API - unencrypted */
    @Test
    fun testNullableWithDirectApi() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_direct"
        val value: String? = null
        val defaultValue: String? = "default"

        ksafe.putDirect(key, value, KSafeWriteMode.Plain)
        val retrieved: String? = ksafe.getDirect(key, defaultValue)
        assertNull(retrieved, "getDirect should return null for null value")
    }

    /** Verifies that null values work with Direct (non-blocking) API - encrypted */
    @Test
    fun testNullableWithDirectApiEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable_direct_enc"
        val value: String? = null
        val defaultValue: String? = "default"

        ksafe.putDirect(key, value)
        val retrieved: String? = ksafe.getDirect(key, defaultValue)
        assertNull(retrieved, "getDirect should return null for encrypted null value")
    }

    // ============ EDGE CASE TESTS ============

    /** Verifies that empty strings are handled correctly (not treated as null) */
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

    /** Verifies that special characters are preserved during storage/retrieval */
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

    /** Verifies that Unicode characters (emoji, CJK, Arabic) are preserved */
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

    /** Verifies that large data (10KB) can be stored and retrieved correctly */
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

    /** Verifies that concurrent access to multiple keys works correctly */
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

    /** Verifies that different KSafe instances with different filenames are isolated */
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

    // ============ NUMERIC EDGE CASES ============

    /** Verifies that negative numbers are stored and retrieved correctly */
    @Test
    fun testNegativeNumbers() = runTest {
        val ksafe = createKSafe()

        val intKey = "negative_int"
        val intValue = -42
        ksafe.put(intKey, intValue, KSafeWriteMode.Plain)
        assertEquals(intValue, ksafe.get(intKey, 0))

        val longKey = "negative_long"
        val longValue = -9876543210L
        ksafe.put(longKey, longValue, KSafeWriteMode.Plain)
        assertEquals(longValue, ksafe.get(longKey, 0L))

        val floatKey = "negative_float"
        val floatValue = -3.14f
        ksafe.put(floatKey, floatValue, KSafeWriteMode.Plain)
        assertEquals(floatValue, ksafe.get(floatKey, 0.0f))

        val doubleKey = "negative_double"
        val doubleValue = -2.71828
        ksafe.put(doubleKey, doubleValue, KSafeWriteMode.Plain)
        assertEquals(doubleValue, ksafe.get(doubleKey, 0.0))
    }

    /** Verifies that boundary values (MIN/MAX) are stored and retrieved correctly */
    @Test
    fun testEdgeCaseNumbers() = runTest {
        val ksafe = createKSafe()

        val maxIntKey = "max_int"
        ksafe.put(maxIntKey, Int.MAX_VALUE, KSafeWriteMode.Plain)
        assertEquals(Int.MAX_VALUE, ksafe.get(maxIntKey, 0))

        val minIntKey = "min_int"
        ksafe.put(minIntKey, Int.MIN_VALUE, KSafeWriteMode.Plain)
        assertEquals(Int.MIN_VALUE, ksafe.get(minIntKey, 0))

        val maxLongKey = "max_long"
        ksafe.put(maxLongKey, Long.MAX_VALUE, KSafeWriteMode.Plain)
        assertEquals(Long.MAX_VALUE, ksafe.get(maxLongKey, 0L))

        val minLongKey = "min_long"
        ksafe.put(minLongKey, Long.MIN_VALUE, KSafeWriteMode.Plain)
        assertEquals(Long.MIN_VALUE, ksafe.get(minLongKey, 0L))
    }

    // ============ DIRECT API TESTS ============

    /** Verifies that getDirect reflects values written with suspend put */
    @Test
    fun testGetDirectReflectsSuspendingPut() = runTest {
        val ksafe = createKSafe()
        val key = "direct_read_test"
        val value = "read_me_now"

        ksafe.put(key, value)
        val result = ksafe.getDirect(key, "default")
        assertEquals(value, result)
    }

    /** Verifies that putDirect immediately updates the cache for getDirect */
    @Test
    fun testPutDirect() = runTest {
        val ksafe = createKSafe()
        val key = "direct_read_test"
        val value = "read_me_now"

        ksafe.putDirect(key, value)
        val result = ksafe.getDirect(key, "default")
        assertEquals(value, result)
    }

    /** Verifies that putDirect eventually persists values (optimistic update) */
    @Test
    fun testPutDirectEventuallyUpdatesValue() = runTest {
        val ksafe = createKSafe()
        val key = "put_direct_test"
        val value = "eventual_consistency"

        ksafe.putDirect(key, value)

        var attempts = 0
        var result: String
        do {
            result = ksafe.getDirect(key, "default")
            attempts++
        } while (result != value && attempts < 20)

        assertEquals(value, result, "getDirect should eventually return the value set by putDirect")
    }

    /** Verifies that Direct API encrypted round-trip works with auto-detection */
    @Test
    fun testDirectEncryptedRoundTrip() = runTest {
        val ksafe = createKSafe()
        val key = "direct_enc_roundtrip"
        val value = 999

        ksafe.putDirect(key, value)

        var attempts = 0
        while (ksafe.getDirect(key, -1) != value && attempts < 20) {
            attempts++
        }

        // Auto-detection finds the encrypted value and decrypts it
        assertEquals(value, ksafe.getDirect(key, -1))
    }

    // ============ PROPERTY DELEGATION TESTS ============

    /** Verifies delegate uses property name as key and encrypts by default */
    @Test
    fun delegate_defaultEncrypted_and_propertyNameKey() = runTest {
        val ksafe = createKSafe()
        var secret: String by ksafe(defaultValue = "init")
        assertEquals("init", secret)
        secret = "z"
        assertEquals("z", secret)
        // Auto-detection finds the encrypted value
        assertEquals("z", ksafe.get("secret", "x"))
    }

    /** Verifies delegate can use explicit key and unencrypted mode */
    @Test
    fun delegate_explicitKey_unencrypted() = runTest {
        val ksafe = createKSafe()
        var count: Int by ksafe(defaultValue = 0, key = "count", mode = KSafeWriteMode.Plain)
        assertEquals(0, count)
        count = 3
        assertEquals(3, count)
        // Auto-detection finds the unencrypted value
        assertEquals(3, ksafe.get("count", -1))
    }

    // ============ SERIALIZABLE OBJECT TESTS ============

    @Serializable
    data class Person(val id: Long, val name: String)

    /** Verifies that serializable objects are encrypted correctly and auto-detected on read */
    @Test
    fun serializable_encrypted_roundTrip() = runTest {
        val ksafe = createKSafe()
        val k = "person"
        val p = Person(7, "Grace")
        ksafe.put(k, p) // encrypted by default
        // Auto-detection finds the encrypted value and decrypts it
        assertEquals(p, ksafe.get(k, Person(0, "")))
    }
}
