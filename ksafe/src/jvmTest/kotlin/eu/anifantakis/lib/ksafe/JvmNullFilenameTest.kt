package eu.anifantakis.lib.ksafe

import app.cash.turbine.test
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.plus
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable
import org.junit.BeforeClass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Locks in: exhaustive single-DataStore coverage (fileName = null), isolating state with per-test unique keys. */
@OptIn(ExperimentalCoroutinesApi::class)
class JvmNullFilenameTest {

    fun createKSafe(fileName: String? = null): KSafe {
        return KSafe(randomName("jvmtest"))
    }

    private fun randomName(prefix: String): String {
        val rnd = kotlin.random.Random
        val sb = StringBuilder(prefix)
        repeat(16) { sb.append(('a' + rnd.nextInt(26))) }
        return sb.toString()
    }

    companion object {
        private lateinit var ksafe: KSafe

        @BeforeClass
        @JvmStatic
        fun setupOnce() {
            ksafe = KSafe(fileName = null)
        }

        private fun uniqueKey(prefix: String) =
            prefix + "_" + java.util.UUID.randomUUID().toString().replace("-", "")
    }

    @Test
    fun get_returnsDefault_whenAbsent_unencrypted() = runTest {
        val key = uniqueKey("absent_plain")
        assertEquals("def", ksafe.get(key, "def"))
    }

    @Test
    fun get_returnsDefault_whenAbsent_encrypted() = runTest {
        val key = uniqueKey("absent_enc")
        assertEquals(42, ksafe.get(key, 42))
    }

    @Test
    fun put_get_defaultEncryption_isEncryptedByDefault() = runTest {
        val key = uniqueKey("default_enc_true")
        ksafe.put(key, "secret")
        assertEquals("secret", ksafe.get(key, "x"))
        assertEquals("secret", ksafe.get(key, "x"))
    }

    @Test
    fun delete_removes_plain_and_returnsDefault() = runTest {
        val key = uniqueKey("plain_delete")
        ksafe.put(key, "v", KSafeWriteMode.Plain)
        assertEquals("v", ksafe.get(key, "d"))
        ksafe.delete(key)
        assertEquals("d", ksafe.get(key, "d"))
    }

    @Test
    fun delete_removes_encrypted_and_returnsDefault() = runTest {
        val key = uniqueKey("enc_delete")
        ksafe.put(key, "v")
        assertEquals("v", ksafe.get(key, "d"))
        ksafe.delete(key)
        assertEquals("d", ksafe.get(key, "d"))
    }

    @Test
    fun direct_plain_roundTrip() {
        val key = uniqueKey("direct_plain")
        ksafe.putDirect(key, "plain_direct", KSafeWriteMode.Plain)
        assertEquals("plain_direct", ksafe.getDirect(key, "d"))
    }

    @Test
    fun direct_encrypted_roundTrip() {
        val key = uniqueKey("direct_enc")
        ksafe.putDirect(key, "enc_direct")
        assertEquals("enc_direct", ksafe.getDirect(key, "d"))
        assertEquals("enc_direct", ksafe.getDirect(key, "d"))
    }

    @Test
    fun delegate_defaultEncrypted_propertyNameAsKey() = runTest {
        val key = uniqueKey("delegate_default")
        var secretValue: String by ksafe(defaultValue = "init_secret")
        secretValue = "init_secret"
        assertEquals("init_secret", secretValue)
        secretValue = "changed"
        assertEquals("changed", secretValue)
        assertEquals("changed", ksafe.get("secretValue", "x"))
        assertEquals("changed", ksafe.get("secretValue", "x"))
    }

    @Test
    fun delegate_explicitKey_unencrypted_roundTrip() = runTest {
        val dKey = uniqueKey("delegate_plain")
        var counter: Int by ksafe(defaultValue = 0, key = dKey, mode = KSafeWriteMode.Plain)
        assertEquals(0, counter)
        counter = 9
        assertEquals(9, counter)
        assertEquals(9, ksafe.get(dKey, -1))
        assertEquals(9, ksafe.get(dKey, -1))
    }

    @Test
    fun flow_unencrypted_emitsOnChange_onlyWhenValueChanges() = runTest {
        val key = uniqueKey("flow_plain")
        val flow = ksafe.getFlow(key, "d")
        flow.test(timeout = 30.seconds) {
            assertEquals("d", awaitItem())
            ksafe.put(key, "a", KSafeWriteMode.Plain)
            assertEquals("a", awaitItem())
            ksafe.put(key, "a", KSafeWriteMode.Plain)
            expectNoEvents()
            ksafe.put(key, "b", KSafeWriteMode.Plain)
            assertEquals("b", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_encrypted_emitsOnChange_onlyWhenValueChanges() = runTest {
        val key = uniqueKey("flow_enc")
        val flow = ksafe.getFlow(key, "d")
        flow.test(timeout = 30.seconds) {
            assertEquals("d", awaitItem())
            ksafe.put(key, "a")
            assertEquals("a", awaitItem())
            ksafe.put(key, "a")
            expectNoEvents()
            ksafe.put(key, "b")
            assertEquals("b", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun stateFlow_unencrypted_hasDefaultAsInitialValue() = runTest {
        val key = uniqueKey("sf_plain")
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, "def", scope = sharingScope)
        assertEquals("def", stateFlow.value)

        ksafe.put(key, "updated", KSafeWriteMode.Plain)
        stateFlow.test(timeout = 30.seconds) {
            assertEquals("updated", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    @Test
    fun stateFlow_encrypted_hasDefaultAsInitialValue() = runTest {
        val key = uniqueKey("sf_enc")
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, "def", scope = sharingScope)
        assertEquals("def", stateFlow.value)

        ksafe.put(key, "secret")
        stateFlow.test(timeout = 30.seconds) {
            // getFlow decrypts on Dispatchers.Default, so the write propagates to the
            // StateFlow asynchronously — an intermediate default emission may precede the
            // written value.
            var item = awaitItem()
            while (item == "def") item = awaitItem()
            assertEquals("secret", item)
            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    @Test
    fun stateFlow_emitsUpdates() = runTest {
        val key = uniqueKey("sf_updates")
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, "def", scope = sharingScope)

        stateFlow.test(timeout = 30.seconds) {
            assertEquals("def", awaitItem())

            ksafe.put(key, "a", KSafeWriteMode.Plain)
            assertEquals("a", awaitItem())

            ksafe.put(key, "b", KSafeWriteMode.Plain)
            assertEquals("b", awaitItem())

            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    @Test
    fun stateFlow_distinctUntilChanged() = runTest {
        val key = uniqueKey("sf_distinct")
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, "def", scope = sharingScope)

        stateFlow.test(timeout = 30.seconds) {
            assertEquals("def", awaitItem())

            ksafe.put(key, "a", KSafeWriteMode.Plain)
            assertEquals("a", awaitItem())

            ksafe.put(key, "a", KSafeWriteMode.Plain)
            expectNoEvents()

            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    @Test
    fun types_boolean_roundTrip() = runTest {
        val key = uniqueKey("bool")
        ksafe.put(key, true)
        assertEquals(true, ksafe.get(key, false))
        assertEquals(true, ksafe.get(key, false))
    }

    @Test
    fun types_int_long_float_double_string_roundTrip_unencrypted() = runTest {
        val iK = uniqueKey("int");    ksafe.put(iK, 123, KSafeWriteMode.Plain);    assertEquals(123, ksafe.get(iK, 0))
        val lK = uniqueKey("long");   ksafe.put(lK, 9999999999L, KSafeWriteMode.Plain);  assertEquals(9999999999L, ksafe.get(lK, 0L))
        val fK = uniqueKey("float");  ksafe.put(fK, 1.5f, KSafeWriteMode.Plain);         assertEquals(1.5f, ksafe.get(fK, 0f))
        val dK = uniqueKey("double"); ksafe.put(dK, 2.5, KSafeWriteMode.Plain);          assertEquals(2.5, ksafe.get(dK, 0.0))
        val sK = uniqueKey("string"); ksafe.put(sK, "hi", KSafeWriteMode.Plain);         assertEquals("hi", ksafe.get(sK, "x"))
    }

    @Serializable
    data class User(val id: Int, val name: String)

    @Test
    fun types_serializable_roundTrip_encrypted() = runTest {
        val key = uniqueKey("user")
        val u = User(1, "Ada")
        ksafe.put(key, u)
        assertEquals(u, ksafe.get(key, User(0, "x")))
        assertEquals(u, ksafe.get(key, User(0, "x")))
    }

    class Settings(private val store: KSafe) {
        var theme: String by store(defaultValue = "light", key = "theme", mode = KSafeWriteMode.Plain)
        var token: String by store(defaultValue = "", key = "token")
        var launchCount: Int by store(defaultValue = 0, key = "launchCount", mode = KSafeWriteMode.Plain)
    }

    @Test
    fun composition_multipleDelegatedProperties_workIndependently() = runTest {
        val s = Settings(ksafe)

        s.theme = "dark"
        s.token = "tkn123"
        s.launchCount = 5

        assertEquals("dark", s.theme)
        assertEquals("tkn123", s.token)
        assertEquals(5, s.launchCount)

        assertEquals("dark", ksafe.get("theme", "x"))
        assertEquals("tkn123", ksafe.get("token", "x"))
    }

    @Test
    fun composition_independentKeys_doNotInterfere() = runTest {
        val s = Settings(ksafe)
        s.theme = "blue"
        s.launchCount = 10
        assertEquals("blue", s.theme)
        assertEquals(10, s.launchCount)
        s.token = "abc"
        assertEquals("blue", s.theme)
        assertEquals(10, s.launchCount)
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

        flow.test(timeout = 30.seconds) {
            assertEquals(defaultValue, awaitItem())

            ksafe.put(key, value1, KSafeWriteMode.Plain)
            assertEquals(value1, awaitItem())

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

        flow.test(timeout = 30.seconds) {
            assertEquals(defaultValue, awaitItem())

            ksafe.put(key, value1)
            assertEquals(value1, awaitItem())

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

        flow.test(timeout = 30.seconds) {
            assertEquals(defaultValue, awaitItem())

            ksafe.put(key, value, KSafeWriteMode.Plain)
            assertEquals(value, awaitItem())

            ksafe.put(key, value, KSafeWriteMode.Plain)
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

        ksafe.put(key1, value1, KSafeWriteMode.Plain)
        ksafe.put(key2, value2, KSafeWriteMode.Plain)

        assertEquals(value1, ksafe.get(key1, defaultValue))
        assertEquals(value2, ksafe.get(key2, defaultValue))

        ksafe.delete(key1)
        assertEquals(defaultValue, ksafe.get(key1, defaultValue))
        assertEquals(value2, ksafe.get(key2, defaultValue))
    }

    @Test
    fun testEncryptedDataIsFoundByAutoDetection() = runTest {
        val ksafe = createKSafe()
        val key = "encryption_test"
        val value = "sensitive_data"
        val defaultValue = "default"

        ksafe.put(key, value)

        val autoDetectedRetrieve = ksafe.get(key, defaultValue)
        assertEquals(value, autoDetectedRetrieve)

        val secondRetrieve = ksafe.get(key, defaultValue)
        assertEquals(value, secondRetrieve)
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

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)

        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value)
        val encryptedRetrieved = ksafe.get(encryptedKey, defaultValue)
        assertEquals(value, encryptedRetrieved)
    }

    @Test
    fun testNullableValues() = runTest {
        val ksafe = createKSafe()
        val key = "test_nullable"
        val value: String? = null
        val defaultValue: String? = "default"

        ksafe.put(key, value, KSafeWriteMode.Plain)
        val retrieved = ksafe.get(key, defaultValue)
        assertEquals(value, retrieved)
    }

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

        ksafe.put(key, value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get(key, defaultValue))

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

        ksafe.put(key, value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get(key, defaultValue))

        val encryptedKey = "${key}_encrypted"
        ksafe.put(encryptedKey, value)
        assertEquals(value, ksafe.get(encryptedKey, defaultValue))
    }

    @Test
    fun testLargeData() = runTest {
        val ksafe = createKSafe()
        val key = "test_large"
        val value = "x".repeat(10000)
        val defaultValue = ""

        ksafe.put(key, value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get(key, defaultValue))

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

    @Test
    fun testGetDirectReflectsSuspendingPut() = runTest {
        val ksafe = createKSafe()
        val key = "direct_read_test"
        val value = "read_me_now"

        ksafe.put(key, value)

        val result = ksafe.getDirect(key, "default")
        assertEquals(value, result)
    }

    @Test
    fun testPutDirect() = runTest {
        val ksafe = createKSafe()
        val key = "direct_read_test"
        val value = "read_me_now"

        ksafe.putDirect(key, value)

        val result = ksafe.getDirect(key, "default")
        assertEquals(value, result)
    }

    @Test
    fun testPutDirectEventuallyUpdatesValue() = runTest {
        val ksafe = createKSafe()
        val key = "put_direct_test"
        val value = "immediate_consistency"

        ksafe.putDirect(key, value)

        val result = ksafe.getDirect(key, "default")

        assertEquals(value, result, "getDirect should immediately return the value set by putDirect")
    }
}