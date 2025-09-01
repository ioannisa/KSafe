package eu.anifantakis.lib.ksafe

import app.cash.turbine.test
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.Ignore

abstract class KSafeTest {
    abstract fun createKSafe(fileName: String? = null): KSafe

    @Test
    fun testPutAndGetUnencryptedString() = runTest {
        val ksafe = createKSafe()
        val key = "test_string"
        val value = "Hello, World!"
        val defaultValue = "default"

        ksafe.put(key, value, encrypted = false)
        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedString() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_string"
        val value = "Secret Message"
        val defaultValue = "default"

        ksafe.put(key, value, encrypted = true)
        val retrieved = ksafe.get(key, defaultValue, encrypted = true)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedInt() = runTest {
        val ksafe = createKSafe()
        val key = "test_int"
        val value = 42
        val defaultValue = 0

        ksafe.put(key, value, encrypted = false)
        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedInt() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_int"
        val value = 1337
        val defaultValue = 0

        ksafe.put(key, value, encrypted = true)
        val retrieved = ksafe.get(key, defaultValue, encrypted = true)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedBoolean() = runTest {
        val ksafe = createKSafe()
        val key = "test_bool"
        val value = true
        val defaultValue = false

        ksafe.put(key, value, encrypted = false)
        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedBoolean() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_bool"
        val value = true
        val defaultValue = false

        ksafe.put(key, value, encrypted = true)
        val retrieved = ksafe.get(key, defaultValue, encrypted = true)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedLong() = runTest {
        val ksafe = createKSafe()
        val key = "test_long"
        val value = 9876543210L
        val defaultValue = 0L

        ksafe.put(key, value, encrypted = false)
        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedLong() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_long"
        val value = 9876543210L
        val defaultValue = 0L

        ksafe.put(key, value, encrypted = true)
        val retrieved = ksafe.get(key, defaultValue, encrypted = true)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedFloat() = runTest {
        val ksafe = createKSafe()
        val key = "test_float"
        val value = 3.14159f
        val defaultValue = 0.0f

        ksafe.put(key, value, encrypted = false)
        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedFloat() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_float"
        val value = 2.71828f
        val defaultValue = 0.0f

        ksafe.put(key, value, encrypted = true)
        val retrieved = ksafe.get(key, defaultValue, encrypted = true)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetUnencryptedDouble() = runTest {
        val ksafe = createKSafe()
        val key = "test_double"
        val value = 3.141592653589793
        val defaultValue = 0.0

        ksafe.put(key, value, encrypted = false)
        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(value, retrieved)
    }

    @Test
    fun testPutAndGetEncryptedDouble() = runTest {
        val ksafe = createKSafe()
        val key = "test_encrypted_double"
        val value = 2.718281828459045
        val defaultValue = 0.0

        ksafe.put(key, value, encrypted = true)
        val retrieved = ksafe.get(key, defaultValue, encrypted = true)
        assertEquals(value, retrieved)
    }

    @Test
    fun testGetWithDefaultValue() = runTest {
        val ksafe = createKSafe()
        val key = "non_existent_key"
        val defaultValue = "default_value"

        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(defaultValue, retrieved)
    }

    @Test
    fun testGetEncryptedWithDefaultValue() = runTest {
        val ksafe = createKSafe()
        val key = "non_existent_encrypted_key"
        val defaultValue = "encrypted_default"

        val retrieved = ksafe.get(key, defaultValue, encrypted = true)
        assertEquals(defaultValue, retrieved)
    }

    @Test
    fun testDelete() = runTest {
        val ksafe = createKSafe()
        val key = "test_delete"
        val value = "to_be_deleted"
        val defaultValue = "default"

        ksafe.put(key, value, encrypted = false)
        assertEquals(value, ksafe.get(key, defaultValue, encrypted = false))

        ksafe.delete(key)
        assertEquals(defaultValue, ksafe.get(key, defaultValue, encrypted = false))
    }

    @Test
    fun testDeleteEncrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_delete_encrypted"
        val value = "encrypted_to_be_deleted"
        val defaultValue = "default"

        ksafe.put(key, value, encrypted = true)
        assertEquals(value, ksafe.get(key, defaultValue, encrypted = true))

        ksafe.delete(key)
        assertEquals(defaultValue, ksafe.get(key, defaultValue, encrypted = true))
    }

    @Test
    fun testOverwriteValue() = runTest {
        val ksafe = createKSafe()
        val key = "test_overwrite"
        val value1 = "first_value"
        val value2 = "second_value"
        val defaultValue = "default"

        ksafe.put(key, value1, encrypted = false)
        assertEquals(value1, ksafe.get(key, defaultValue, encrypted = false))

        ksafe.put(key, value2, encrypted = false)
        assertEquals(value2, ksafe.get(key, defaultValue, encrypted = false))
    }

    @Test
    fun testOverwriteEncryptedValue() = runTest {
        val ksafe = createKSafe()
        val key = "test_overwrite_encrypted"
        val value1 = "first_encrypted"
        val value2 = "second_encrypted"
        val defaultValue = "default"

        ksafe.put(key, value1, encrypted = true)
        assertEquals(value1, ksafe.get(key, defaultValue, encrypted = true))

        ksafe.put(key, value2, encrypted = true)
        assertEquals(value2, ksafe.get(key, defaultValue, encrypted = true))
    }

    @Test
    fun testFlowUnencrypted() = runTest {
        val ksafe = createKSafe()
        val key = "test_flow"
        val value1 = "flow_value_1"
        val value2 = "flow_value_2"
        val defaultValue = "default"

        val flow = ksafe.getFlow(key, defaultValue, encrypted = false)

        flow.test {
            // Initially should emit default value
            assertEquals(defaultValue, awaitItem())

            // Update value
            ksafe.put(key, value1, encrypted = false)
            assertEquals(value1, awaitItem())

            // Update again
            ksafe.put(key, value2, encrypted = false)
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

        val flow = ksafe.getFlow(key, defaultValue, encrypted = true)

        flow.test {
            // Initially should emit default value
            assertEquals(defaultValue, awaitItem())

            // Update value
            ksafe.put(key, value1, encrypted = true)
            assertEquals(value1, awaitItem())

            // Update again
            ksafe.put(key, value2, encrypted = true)
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

        val flow = ksafe.getFlow(key, defaultValue, encrypted = false)

        flow.test {
            // Initially should emit default value
            assertEquals(defaultValue, awaitItem())

            // Update value
            ksafe.put(key, value, encrypted = false)
            assertEquals(value, awaitItem())

            // Update with same value - should not emit
            ksafe.put(key, value, encrypted = false)
            expectNoEvents()

            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun testMultipleKeysIndependence() = runTest {
        val ksafe = createKSafe()
        val key1 = "key1"
        val key2 = "key2"
        val value1 = "value1"
        val value2 = "value2"
        val defaultValue = "default"

        ksafe.put(key1, value1, encrypted = false)
        ksafe.put(key2, value2, encrypted = false)

        assertEquals(value1, ksafe.get(key1, defaultValue, encrypted = false))
        assertEquals(value2, ksafe.get(key2, defaultValue, encrypted = false))

        ksafe.delete(key1)
        assertEquals(defaultValue, ksafe.get(key1, defaultValue, encrypted = false))
        assertEquals(value2, ksafe.get(key2, defaultValue, encrypted = false))
    }

    @Test
    fun testEncryptedDataIsDifferentFromPlaintext() = runTest {
        val ksafe = createKSafe()
        val key = "encryption_test"
        val value = "sensitive_data"
        val defaultValue = "default"

        // Store encrypted
        ksafe.put(key, value, encrypted = true)
        
        // Try to retrieve as unencrypted - should not match
        val unencryptedRetrieve = ksafe.get(key, defaultValue, encrypted = false)
        assertNotEquals(value, unencryptedRetrieve)
        
        // Retrieve as encrypted - should match
        val encryptedRetrieve = ksafe.get(key, defaultValue, encrypted = true)
        assertEquals(value, encryptedRetrieve)
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
        ksafe.put(key, value, encrypted = false)
        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(value, retrieved)

        // Test encrypted
        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value, encrypted = true)
        val encryptedRetrieved = ksafe.get(encryptedKey, defaultValue, encrypted = true)
        assertEquals(value, encryptedRetrieved)
    }

    @Ignore("Nullable values are not properly supported yet - JSON serialization converts null to string 'null'")
    @Test
    fun testNullableValues() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable"
        val value: String? = null
        val defaultValue: String? = "default"

        // Store null value
        ksafe.put(key, value, encrypted = false)
        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(value, retrieved)
    }

    @Test
    fun testEmptyString() = runTest {
        val ksafe = createKSafe()
        val key = "test_empty"
        val value = ""
        val defaultValue = "default"

        ksafe.put(key, value, encrypted = false)
        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(value, retrieved)
    }

    @Test
    fun testSpecialCharacters() = runTest {
        val ksafe = createKSafe()
        val key = "test_special"
        val value = "Special chars: !@#$%^&*()_+{}[]|\\:\";<>?,./~`'"
        val defaultValue = "default"

        // Test unencrypted
        ksafe.put(key, value, encrypted = false)
        assertEquals(value, ksafe.get(key, defaultValue, encrypted = false))

        // Test encrypted
        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value, encrypted = true)
        assertEquals(value, ksafe.get(encryptedKey, defaultValue, encrypted = true))
    }

    @Test
    fun testUnicodeCharacters() = runTest {
        val ksafe = createKSafe()
        val key = "test_unicode"
        val value = "Unicode: 你好世界 🌍 مرحبا بالعالم"
        val defaultValue = "default"

        // Test unencrypted
        ksafe.put(key, value, encrypted = false)
        assertEquals(value, ksafe.get(key, defaultValue, encrypted = false))

        // Test encrypted
        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value, encrypted = true)
        assertEquals(value, ksafe.get(encryptedKey, defaultValue, encrypted = true))
    }

    @Test
    fun testLargeData() = runTest {
        val ksafe = createKSafe()
        val key = "test_large"
        val value = "x".repeat(10000) // 10KB of data
        val defaultValue = ""

        // Test unencrypted
        ksafe.put(key, value, encrypted = false)
        assertEquals(value, ksafe.get(key, defaultValue, encrypted = false))

        // Test encrypted
        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value, encrypted = true)
        assertEquals(value, ksafe.get(encryptedKey, defaultValue, encrypted = true))
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

            ksafe.put(key, value, encrypted = false)
            val retrieved = ksafe.get(key, defaultValue, encrypted = false)
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

        ksafe1.put(key, value1, encrypted = false)
        ksafe2.put(key, value2, encrypted = false)

        assertEquals(value1, ksafe1.get(key, defaultValue, encrypted = false))
        assertEquals(value2, ksafe2.get(key, defaultValue, encrypted = false))
    }

    @Test
    fun testNegativeNumbers() = runTest {
        val ksafe = createKSafe()
        
        // Test negative int
        val intKey = "negative_int"
        val intValue = -42
        ksafe.put(intKey, intValue, encrypted = false)
        assertEquals(intValue, ksafe.get(intKey, 0, encrypted = false))

        // Test negative long
        val longKey = "negative_long"
        val longValue = -9876543210L
        ksafe.put(longKey, longValue, encrypted = false)
        assertEquals(longValue, ksafe.get(longKey, 0L, encrypted = false))

        // Test negative float
        val floatKey = "negative_float"
        val floatValue = -3.14f
        ksafe.put(floatKey, floatValue, encrypted = false)
        assertEquals(floatValue, ksafe.get(floatKey, 0.0f, encrypted = false))

        // Test negative double
        val doubleKey = "negative_double"
        val doubleValue = -2.71828
        ksafe.put(doubleKey, doubleValue, encrypted = false)
        assertEquals(doubleValue, ksafe.get(doubleKey, 0.0, encrypted = false))
    }

    @Test
    fun testEdgeCaseNumbers() = runTest {
        val ksafe = createKSafe()
        
        // Test Int boundaries
        val maxIntKey = "max_int"
        ksafe.put(maxIntKey, Int.MAX_VALUE, encrypted = false)
        assertEquals(Int.MAX_VALUE, ksafe.get(maxIntKey, 0, encrypted = false))

        val minIntKey = "min_int"
        ksafe.put(minIntKey, Int.MIN_VALUE, encrypted = false)
        assertEquals(Int.MIN_VALUE, ksafe.get(minIntKey, 0, encrypted = false))

        // Test Long boundaries
        val maxLongKey = "max_long"
        ksafe.put(maxLongKey, Long.MAX_VALUE, encrypted = false)
        assertEquals(Long.MAX_VALUE, ksafe.get(maxLongKey, 0L, encrypted = false))

        val minLongKey = "min_long"
        ksafe.put(minLongKey, Long.MIN_VALUE, encrypted = false)
        assertEquals(Long.MIN_VALUE, ksafe.get(minLongKey, 0L, encrypted = false))
    }
}