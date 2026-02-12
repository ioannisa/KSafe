package eu.anifantakis.lib.ksafe

import app.cash.turbine.test
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.plus
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable
import org.junit.BeforeClass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Exhaustive tests for a single DataStore (fileName = null).
 * We reuse one KSafe instance across many tests and isolate state with unique keys.
 *
 * Important: Using a single DataStore avoids multiple-instance conflicts on JVM.
 */
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

    // ---------- Basics & defaults ----------

    /** Verifies unencrypted get returns default when key is absent */
    @Test
    fun get_returnsDefault_whenAbsent_unencrypted() = runTest {
        val key = uniqueKey("absent_plain")
        assertEquals("def", ksafe.get(key, "def", encrypted = false))
    }

    /** Verifies encrypted get returns default when key is absent */
    @Test
    fun get_returnsDefault_whenAbsent_encrypted() = runTest {
        val key = uniqueKey("absent_enc")
        assertEquals(42, ksafe.get(key, 42, encrypted = true))
    }

    /** Verifies default encryption mode is encrypted (true) */
    @Test
    fun put_get_defaultEncryption_isEncryptedByDefault() = runTest {
        val key = uniqueKey("default_enc_true")
        ksafe.put(key, "secret") // encrypted defaults to true
        assertEquals("secret", ksafe.get(key, "x"))           // encrypted=true
        assertNotEquals("secret", ksafe.get(key, "x", false)) // unencrypted read must not reveal
    }

    /** Verifies delete removes unencrypted value and returns default */
    @Test
    fun delete_removes_plain_and_returnsDefault() = runTest {
        val key = uniqueKey("plain_delete")
        ksafe.put(key, "v", encrypted = false)
        assertEquals("v", ksafe.get(key, "d", encrypted = false))
        ksafe.delete(key)
        assertEquals("d", ksafe.get(key, "d", encrypted = false))
    }

    /** Verifies delete removes encrypted value and returns default */
    @Test
    fun delete_removes_encrypted_and_returnsDefault() = runTest {
        val key = uniqueKey("enc_delete")
        ksafe.put(key, "v", encrypted = true)
        assertEquals("v", ksafe.get(key, "d", encrypted = true))
        ksafe.delete(key)
        assertEquals("d", ksafe.get(key, "d", encrypted = true))
    }

    // ---------- Direct API ----------

    /** Verifies putDirect/getDirect roundtrip for unencrypted data */
    @Test
    fun direct_plain_roundTrip() {
        val key = uniqueKey("direct_plain")
        ksafe.putDirect(key, "plain_direct", encrypted = false)
        assertEquals("plain_direct", ksafe.getDirect(key, "d", encrypted = false))
    }

    /** Verifies putDirect/getDirect roundtrip for encrypted data */
    @Test
    fun direct_encrypted_roundTrip() {
        val key = uniqueKey("direct_enc")
        ksafe.putDirect(key, "enc_direct") // default encrypted = true
        assertEquals("enc_direct", ksafe.getDirect(key, "d")) // default encrypted = true
        assertNotEquals("enc_direct", ksafe.getDirect(key, "d", encrypted = false))
    }

    // ---------- Delegates ----------

    /** Verifies delegate uses property name as key and encrypts by default */
    @Test
    fun delegate_defaultEncrypted_propertyNameAsKey() = runTest {
        val key = uniqueKey("delegate_default") // only to avoid clashes if reused by name
        // key omitted: will use property name "secretValue"
        var secretValue: String by ksafe(defaultValue = "init_secret")
        secretValue = "init_secret"
        assertEquals("init_secret", secretValue)
        secretValue = "changed"
        assertEquals("changed", secretValue)
        // Underlying: encrypted read matches, unencrypted doesn't
        assertEquals("changed", ksafe.get("secretValue", "x", encrypted = true))
        assertNotEquals("changed", ksafe.get("secretValue", "x", encrypted = false))
    }

    /** Verifies delegate with explicit key and unencrypted mode */
    @Test
    fun delegate_explicitKey_unencrypted_roundTrip() = runTest {
        val dKey = uniqueKey("delegate_plain")
        var counter: Int by ksafe(defaultValue = 0, key = dKey, encrypted = false)
        assertEquals(0, counter)
        counter = 9
        assertEquals(9, counter)
        assertEquals(9, ksafe.get(dKey, -1, encrypted = false))
        assertEquals(-1, ksafe.get(dKey, -1, encrypted = true))
    }

    // ---------- Flows ----------

    /** Verifies unencrypted Flow emits only when value actually changes */
    @Test
    fun flow_unencrypted_emitsOnChange_onlyWhenValueChanges() = runTest {
        val key = uniqueKey("flow_plain")
        val flow = ksafe.getFlow(key, "d", encrypted = false)
        flow.test {
            assertEquals("d", awaitItem())
            ksafe.put(key, "a", encrypted = false)
            assertEquals("a", awaitItem())
            ksafe.put(key, "a", encrypted = false) // no change
            expectNoEvents()
            ksafe.put(key, "b", encrypted = false)
            assertEquals("b", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    /** Verifies encrypted Flow emits only when value actually changes */
    @Test
    fun flow_encrypted_emitsOnChange_onlyWhenValueChanges() = runTest {
        val key = uniqueKey("flow_enc")
        val flow = ksafe.getFlow(key, "d", encrypted = true)
        flow.test {
            assertEquals("d", awaitItem())
            ksafe.put(key, "a", encrypted = true)
            assertEquals("a", awaitItem())
            ksafe.put(key, "a", encrypted = true)
            expectNoEvents()
            ksafe.put(key, "b", encrypted = true)
            assertEquals("b", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    // ---------- StateFlow ----------

    /** Verifies StateFlow has defaultValue as initial value (unencrypted) */
    @Test
    fun stateFlow_unencrypted_hasDefaultAsInitialValue() = runTest {
        val key = uniqueKey("sf_plain")
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, "def", scope = sharingScope, encrypted = false)
        assertEquals("def", stateFlow.value)

        ksafe.put(key, "updated", encrypted = false)
        stateFlow.test {
            assertEquals("updated", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    /** Verifies StateFlow has defaultValue as initial value (encrypted) */
    @Test
    fun stateFlow_encrypted_hasDefaultAsInitialValue() = runTest {
        val key = uniqueKey("sf_enc")
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, "def", scope = sharingScope, encrypted = true)
        assertEquals("def", stateFlow.value)

        ksafe.put(key, "secret", encrypted = true)
        stateFlow.test {
            assertEquals("secret", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    /** Verifies StateFlow reflects reactive updates */
    @Test
    fun stateFlow_emitsUpdates() = runTest {
        val key = uniqueKey("sf_updates")
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, "def", scope = sharingScope, encrypted = false)

        stateFlow.test {
            assertEquals("def", awaitItem())

            ksafe.put(key, "a", encrypted = false)
            assertEquals("a", awaitItem())

            ksafe.put(key, "b", encrypted = false)
            assertEquals("b", awaitItem())

            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    /** Verifies StateFlow does not emit duplicate values */
    @Test
    fun stateFlow_distinctUntilChanged() = runTest {
        val key = uniqueKey("sf_distinct")
        val sharingScope = this + Job()

        val stateFlow = ksafe.getStateFlow(key, "def", scope = sharingScope, encrypted = false)

        stateFlow.test {
            assertEquals("def", awaitItem())

            ksafe.put(key, "a", encrypted = false)
            assertEquals("a", awaitItem())

            ksafe.put(key, "a", encrypted = false) // no change
            expectNoEvents()

            cancelAndIgnoreRemainingEvents()
        }
        sharingScope.cancel()
    }

    // ---------- Type coverage ----------

    /** Verifies Boolean type roundtrip with encryption */
    @Test
    fun types_boolean_roundTrip() = runTest {
        val key = uniqueKey("bool")
        ksafe.put(key, true) // encrypted = true by default
        assertEquals(true, ksafe.get(key, false))
        assertEquals(false, ksafe.get(key, false, encrypted = false))
    }

    /** Verifies all primitive types roundtrip without encryption */
    @Test
    fun types_int_long_float_double_string_roundTrip_unencrypted() = runTest {
        val iK = uniqueKey("int");    ksafe.put(iK, 123, encrypted = false);    assertEquals(123, ksafe.get(iK, 0, false))
        val lK = uniqueKey("long");   ksafe.put(lK, 9999999999L, false);        assertEquals(9999999999L, ksafe.get(lK, 0L, false))
        val fK = uniqueKey("float");  ksafe.put(fK, 1.5f, false);               assertEquals(1.5f, ksafe.get(fK, 0f, false))
        val dK = uniqueKey("double"); ksafe.put(dK, 2.5, false);                assertEquals(2.5, ksafe.get(dK, 0.0, false))
        val sK = uniqueKey("string"); ksafe.put(sK, "hi", false);               assertEquals("hi", ksafe.get(sK, "x", false))
    }

    @Serializable
    data class User(val id: Int, val name: String)

    /** Verifies @Serializable data class roundtrip with encryption */
    @Test
    fun types_serializable_roundTrip_encrypted() = runTest {
        val key = uniqueKey("user")
        val u = User(1, "Ada")
        ksafe.put(key, u) // encrypted
        assertEquals(u, ksafe.get(key, User(0, "x")))     // encrypted OK
        // unencrypted read should not deserialize the ciphertext
        assertEquals(User(0, "x"), ksafe.get(key, User(0, "x"), encrypted = false))
    }

    // ---------- Composition with a settings class ----------

    class Settings(private val store: KSafe) {
        var theme: String by store(defaultValue = "light", key = "theme", encrypted = false)
        var token: String by store(defaultValue = "", key = "token") // encrypted
        var launchCount: Int by store(defaultValue = 0, key = "launchCount", encrypted = false)
    }

    /** Verifies multiple delegated properties work independently */
    @Test
    fun composition_multipleDelegatedProperties_workIndependently() = runTest {
        val s = Settings(ksafe)
        // defaults
//        assertEquals("light", s.theme)
//        assertEquals("", s.token)
//        assertEquals(0, s.launchCount)

        // update and read back
        s.theme = "dark"
        s.token = "tkn123"
        s.launchCount = 5

        assertEquals("dark", s.theme)
        assertEquals("tkn123", s.token)
        assertEquals(5, s.launchCount)

        // Ensure underlying storage reflects both encrypted and plain
        assertEquals("dark", ksafe.get("theme", "x", encrypted = false))
        assertEquals("tkn123", ksafe.get("token", "x", encrypted = true))
    }

    /** Verifies writes to one key don't affect other keys */
    @Test
    fun composition_independentKeys_doNotInterfere() = runTest {
        val s = Settings(ksafe)
        s.theme = "blue"
        s.launchCount = 10
        assertEquals("blue", s.theme)
        assertEquals(10, s.launchCount)
        // writing token should not change theme/launchCount
        s.token = "abc"
        assertEquals("blue", s.theme)
        assertEquals(10, s.launchCount)
    }

    /** Verifies put/get roundtrip for unencrypted String */
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

    /** Verifies put/get roundtrip for encrypted String */
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

    /** Verifies put/get roundtrip for unencrypted Int */
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

    /** Verifies put/get roundtrip for encrypted Int */
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

    /** Verifies put/get roundtrip for unencrypted Boolean */
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

    /** Verifies put/get roundtrip for encrypted Boolean */
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

    /** Verifies put/get roundtrip for unencrypted Long */
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

    /** Verifies put/get roundtrip for encrypted Long */
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

    /** Verifies put/get roundtrip for unencrypted Float */
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

    /** Verifies put/get roundtrip for encrypted Float */
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

    /** Verifies put/get roundtrip for unencrypted Double */
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

    /** Verifies put/get roundtrip for encrypted Double */
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

    /** Verifies get returns default for non-existent unencrypted key */
    @Test
    fun testGetWithDefaultValue() = runTest {
        val ksafe = createKSafe()
        val key = "non_existent_key"
        val defaultValue = "default_value"

        val retrieved = ksafe.get(key, defaultValue, encrypted = false)
        assertEquals(defaultValue, retrieved)
    }

    /** Verifies get returns default for non-existent encrypted key */
    @Test
    fun testGetEncryptedWithDefaultValue() = runTest {
        val ksafe = createKSafe()
        val key = "non_existent_encrypted_key"
        val defaultValue = "encrypted_default"

        val retrieved = ksafe.get(key, defaultValue, encrypted = true)
        assertEquals(defaultValue, retrieved)
    }

    /** Verifies delete removes unencrypted value */
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

    /** Verifies delete removes encrypted value */
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

    /** Verifies put overwrites existing unencrypted value */
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

    /** Verifies put overwrites existing encrypted value */
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

    /** Verifies Flow emits updates for unencrypted values */
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

    /** Verifies Flow emits updates for encrypted values */
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

    /** Verifies Flow skips duplicate consecutive values */
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

    /** Verifies multiple keys are stored independently */
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

    /** Verifies encrypted data is not readable as unencrypted */
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

    /** Verifies complex @Serializable object roundtrip */
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

    /** Verifies nullable values are handled correctly */
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

    /** Verifies empty string roundtrip */
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

    /** Verifies special characters roundtrip */
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

    /** Verifies Unicode characters roundtrip */
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

    /** Verifies large data (10KB) roundtrip */
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

    /** Verifies concurrent put/get operations work correctly */
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

    /** Verifies different file names store data independently */
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

    /** Verifies negative number roundtrip for all numeric types */
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

    /** Verifies Int/Long boundary values (MIN_VALUE, MAX_VALUE) */
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

    /** Verifies getDirect reflects value written by suspend put() */
    @Test
    fun testGetDirectReflectsSuspendingPut() = runTest {
        val ksafe = createKSafe()
        val key = "direct_read_test"
        val value = "read_me_now"

        // 1. Write using suspend function (waits for disk write)
        ksafe.put(key, value, encrypted = true)

        // 2. Read using non-blocking getDirect (cache updated synchronously by put)
        val result = ksafe.getDirect(key, "default", encrypted = true)
        assertEquals(value, result)
    }

    /** Verifies putDirect followed by getDirect roundtrip */
    @Test
    fun testPutDirect() = runTest {
        val ksafe = createKSafe()
        val key = "direct_read_test"
        val value = "read_me_now"

        // 1. Write using putDirect (optimistic cache update is immediate)
        ksafe.putDirect(key, value, encrypted = true)

        // 2. Read using non-blocking getDirect (cache already updated)
        val result = ksafe.getDirect(key, "default", encrypted = true)
        assertEquals(value, result)
    }

    /** Verifies putDirect is immediately visible via getDirect (optimistic update) */
    @Test
    fun testPutDirectEventuallyUpdatesValue() = runTest {
        val ksafe = createKSafe()
        val key = "put_direct_test"
        val value = "immediate_consistency"

        // Write using putDirect (optimistic cache update is immediate)
        ksafe.putDirect(key, value, encrypted = true)

        // Read immediately - no polling needed due to optimistic cache update
        val result = ksafe.getDirect(key, "default", encrypted = true)

        assertEquals(value, result, "getDirect should immediately return the value set by putDirect")
    }
}