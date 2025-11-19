package eu.anifantakis.lib.ksafe

import app.cash.turbine.test
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlin.test.*
import kotlinx.serialization.Serializable

/**
 * Exhaustive tests for custom file names (letters-only).
 * Each test uses a unique file name to avoid DataStore instance conflicts.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class JvmFileNameTest {

    private fun randomName(prefix: String): String {
        val rnd = kotlin.random.Random
        val sb = StringBuilder(prefix)
        repeat(8) { sb.append(('a' + rnd.nextInt(26))) }
        return sb.toString()
    }

    private fun newStore(): KSafe = KSafe(randomName("store"))

    // ---------- Filename validation ----------

    @Test
    fun filename_rejects_nonLetters() {
        assertFailsWith<IllegalArgumentException> { KSafe("abc123") }
        assertFailsWith<IllegalArgumentException> { KSafe("with_underscore") }
        assertFailsWith<IllegalArgumentException> { KSafe("UPPER") }
        assertFailsWith<IllegalArgumentException> { KSafe("") }
    }

    // ---------- Isolation between file names ----------

    @Test
    fun isolation_sameKeys_doNotLeakAcrossDifferentFiles() = runTest {
        val s1 = newStore()
        val s2 = newStore()
        val key = "shared"
        s1.put(key, "v1", encrypted = false)
        s2.put(key, "v2", encrypted = false)
        assertEquals("v1", s1.get(key, "x", false))
        assertEquals("v2", s2.get(key, "x", false))
    }

    // ---------- Encryption behavior ----------

    @Test
    fun encryption_readWithWrongModeDoesNotReveal() = runTest {
        val s = newStore()
        val k = "ek"
        s.put(k, "secret") // encrypted by default
        assertEquals("secret", s.get(k, "x"))            // encrypted
        assertNotEquals("secret", s.get(k, "x", false))  // unencrypted
    }

    @Test
    fun unencrypted_roundTrip() = runTest {
        val s = newStore()
        val k = "plain"
        s.put(k, "p", encrypted = false)
        assertEquals("p", s.get(k, "x", encrypted = false))
    }

    // ---------- Flows ----------

    @Test
    fun flow_unencrypted_emitsChanges() = runTest {
        val s = newStore()
        val k = "f_plain"
        s.getFlow(k, "d", false).test {
            assertEquals("d", awaitItem())
            s.put(k, "a", false)
            assertEquals("a", awaitItem())
            s.put(k, "b", false)
            assertEquals("b", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_encrypted_emitsChanges() = runTest {
        val s = newStore()
        val k = "f_enc"
        s.getFlow(k, 0, true).test {
            assertEquals(0, awaitItem())
            s.put(k, 1, true)
            assertEquals(1, awaitItem())
            s.put(k, 2, true)
            assertEquals(2, awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    // ---------- Delegates ----------

    @Test
    fun delegate_defaultEncrypted_and_propertyNameKey() = runTest {
        val s = newStore()
        var secret: String by s(defaultValue = "init")
        assertEquals("init", secret)
        secret = "z"
        assertEquals("z", secret)
        assertEquals("z", s.get("secret", "x", true))
        assertNotEquals("z", s.get("secret", "x", false))
    }

    @Test
    fun delegate_explicitKey_unencrypted() = runTest {
    val s = newStore()
        var count: Int by s(defaultValue = 0, key = "count", encrypted = false)
        assertEquals(0, count)
        count = 3
        assertEquals(3, count)
        assertEquals(3, s.get("count", -1, false))
        assertEquals(-1, s.get("count", -1, true))
    }

    // ---------- Types ----------

    @Test
    fun primitives_unencrypted_roundTrip() = runTest {
        val s = newStore()
        s.put("i", 1, false); assertEquals(1, s.get("i", 0, false))
        s.put("l", 2L, false); assertEquals(2L, s.get("l", 0L, false))
        s.put("f", 1.5f, false); assertEquals(1.5f, s.get("f", 0f, false))
        s.put("d", 2.5, false); assertEquals(2.5, s.get("d", 0.0, false))
        s.put("b", true, false); assertEquals(true, s.get("b", false, false))
        s.put("s", "hi", false); assertEquals("hi", s.get("s", "x", false))
    }

    @Serializable
    data class Person(val id: Long, val name: String)

    @Test
    fun serializable_encrypted_roundTrip() = runTest {
        val s = newStore()
        val k = "person"
        val p = Person(7, "Grace")
        s.put(k, p) // encrypted
        assertEquals(p, s.get(k, Person(0, "")))
        // ciphertext should not be decodable in plaintext mode
        assertEquals(Person(0, ""), s.get(k, Person(0, ""), encrypted = false))
    }

    // ---------- Delete ----------

    @Test
    fun delete_plain_and_encrypted() = runTest {
        val s = newStore()
        val kp = "plainDel"; val ke = "encDel"
        s.put(kp, "p", false); s.put(ke, "e", true)
        s.delete(kp); s.delete(ke)
        assertEquals("x", s.get(kp, "x", false))
        assertEquals("x", s.get(ke, "x", true))
    }

    // ---------- Composition ----------

    class Prefs(private val s: KSafe) {
        var theme: String by s(defaultValue = "light", key = "theme", encrypted = false)
        var auth: String by s(defaultValue = "", key = "auth") // encrypted
        var level: Int by s(defaultValue = 0, key = "level", encrypted = false)
    }

    @Test
    fun composition_multipleInstances_isolatePerFile() = runTest {
        val a = Prefs(newStore())
        val b = Prefs(newStore())
        a.theme = "dark"; a.auth = "aaa"; a.level = 1
        b.theme = "blue"; b.auth = "bbb"; b.level = 2

        assertEquals("dark", a.theme); assertEquals("blue", b.theme)
        assertEquals("aaa", a.auth); assertEquals("bbb", b.auth)
        assertEquals(1, a.level); assertEquals(2, b.level)
    }

    @Test
    fun composition_updates_visibleViaDirectAPI() = runTest {
        val s = newStore(); val p = Prefs(s)
        p.theme = "green"; p.auth = "tok"; p.level = 4
        assertEquals("green", s.get("theme", "x", false))
        assertEquals("tok", s.get("auth", "x", true))
        assertEquals(4, s.get("level", -1, false))
    }
}