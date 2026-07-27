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
            // A StateFlow's first emission is whatever it currently holds, which is still the
            // default until the write propagates — same race the encrypted twin below tolerates.
            var item = awaitItem()
            while (item == "def") item = awaitItem()
            assertEquals("updated", item)
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
    fun testPutDirectEventuallyUpdatesValue() = runTest {
        val ksafe = createKSafe()
        val key = "put_direct_test"
        val value = "immediate_consistency"

        ksafe.putDirect(key, value)

        val result = ksafe.getDirect(key, "default")

        assertEquals(value, result, "getDirect should immediately return the value set by putDirect")
    }
}