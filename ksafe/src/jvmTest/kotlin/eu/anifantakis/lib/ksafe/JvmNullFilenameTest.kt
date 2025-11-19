package eu.anifantakis.lib.ksafe

import app.cash.turbine.test
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlin.test.*
import kotlinx.serialization.Serializable
import org.junit.BeforeClass

/**
 * Exhaustive tests for a single DataStore (fileName = null).
 * We reuse one KSafe instance across many tests and isolate state with unique keys.
 *
 * Important: Using a single DataStore avoids multiple-instance conflicts on JVM.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class JvmNullFilenameTest {

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

    @Test
    fun get_returnsDefault_whenAbsent_unencrypted() = runTest {
        val key = uniqueKey("absent_plain")
        assertEquals("def", ksafe.get(key, "def", encrypted = false))
    }

    @Test
    fun get_returnsDefault_whenAbsent_encrypted() = runTest {
        val key = uniqueKey("absent_enc")
        assertEquals(42, ksafe.get(key, 42, encrypted = true))
    }

    @Test
    fun put_get_defaultEncryption_isEncryptedByDefault() = runTest {
        val key = uniqueKey("default_enc_true")
        ksafe.put(key, "secret") // encrypted defaults to true
        assertEquals("secret", ksafe.get(key, "x"))           // encrypted=true
        assertNotEquals("secret", ksafe.get(key, "x", false)) // unencrypted read must not reveal
    }

    @Test
    fun delete_removes_plain_and_returnsDefault() = runTest {
        val key = uniqueKey("plain_delete")
        ksafe.put(key, "v", encrypted = false)
        assertEquals("v", ksafe.get(key, "d", encrypted = false))
        ksafe.delete(key)
        assertEquals("d", ksafe.get(key, "d", encrypted = false))
    }

    @Test
    fun delete_removes_encrypted_and_returnsDefault() = runTest {
        val key = uniqueKey("enc_delete")
        ksafe.put(key, "v", encrypted = true)
        assertEquals("v", ksafe.get(key, "d", encrypted = true))
        ksafe.delete(key)
        assertEquals("d", ksafe.get(key, "d", encrypted = true))
    }

    // ---------- Direct API ----------

    @Test
    fun direct_plain_roundTrip() {
        val key = uniqueKey("direct_plain")
        ksafe.putDirect(key, "plain_direct", encrypted = false)
        assertEquals("plain_direct", ksafe.getDirect(key, "d", encrypted = false))
    }

    @Test
    fun direct_encrypted_roundTrip() {
        val key = uniqueKey("direct_enc")
        ksafe.putDirect(key, "enc_direct") // default encrypted = true
        assertEquals("enc_direct", ksafe.getDirect(key, "d")) // default encrypted = true
        assertNotEquals("enc_direct", ksafe.getDirect(key, "d", encrypted = false))
    }

    // ---------- Delegates ----------

    @Test
    fun delegate_defaultEncrypted_propertyNameAsKey() = runTest {
        val key = uniqueKey("delegate_default") // only to avoid clashes if reused by name
        // key omitted: will use property name "secretValue"
        var secretValue: String by ksafe(defaultValue = "init_secret")
        assertEquals("init_secret", secretValue)
        secretValue = "changed"
        assertEquals("changed", secretValue)
        // Underlying: encrypted read matches, unencrypted doesn't
        assertEquals("changed", ksafe.get("secretValue", "x", encrypted = true))
        assertNotEquals("changed", ksafe.get("secretValue", "x", encrypted = false))
    }

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

    // ---------- Type coverage ----------

    @Test
    fun types_boolean_roundTrip() = runTest {
        val key = uniqueKey("bool")
        ksafe.put(key, true) // encrypted = true by default
        assertEquals(true, ksafe.get(key, false))
        assertEquals(false, ksafe.get(key, false, encrypted = false))
    }

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

    @Test
    fun composition_multipleDelegatedProperties_workIndependently() = runTest {
        val s = Settings(ksafe)
        // defaults
        assertEquals("light", s.theme)
        assertEquals("", s.token)
        assertEquals(0, s.launchCount)

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
}