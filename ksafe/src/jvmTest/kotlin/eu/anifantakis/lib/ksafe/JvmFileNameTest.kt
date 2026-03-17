package eu.anifantakis.lib.ksafe

import app.cash.turbine.test
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlin.test.*
import kotlinx.serialization.Serializable

/**
 * Exhaustive tests for custom file names (letters-only).
 * Each test uses a unique file name to avoid DataStore instance conflicts.
 *
 * Tests cover:
 * - Filename validation (letters-only requirement)
 * - Isolation between different file names
 * - Encryption behavior
 * - Flow emissions
 * - Property delegates
 * - Type support (primitives, serializable)
 * - Delete operations
 * - Composition patterns
 */
@OptIn(ExperimentalCoroutinesApi::class)
class JvmFileNameTest {

    companion object {
        // Atomic counter to ensure unique file names across all tests in a single run
        private val testCounter = java.util.concurrent.atomic.AtomicInteger(0)

        // Timestamp prefix ensures uniqueness across test runs
        // Convert to base-26 letters since KSafe only allows [a-z]+
        private val runId: String = numberToLetters(System.currentTimeMillis())

        /**
         * Generates a unique file name using only lowercase letters.
         * KSafe requires file names to match regex [a-z]+
         */
        private fun generateUniqueFileName(): String {
            val count = testCounter.incrementAndGet()
            return "fnrun${runId}test${numberToLetters(count.toLong())}"
        }

        private fun numberToLetters(num: Long): String {
            var n = num
            val sb = StringBuilder()
            while (n > 0) {
                n-- // Adjust for 0-based indexing
                sb.insert(0, ('a' + (n % 26).toInt()))
                n /= 26
            }
            return if (sb.isEmpty()) "a" else sb.toString()
        }
    }

    private fun newStore(): KSafe = KSafe(generateUniqueFileName())

    // ---------- Filename validation ----------

    /** Verifies filename validation accepts lowercase letters, digits, and underscores */
    @Test
    fun filename_accepts_valid_names() {
        // These should not throw
        KSafe("abc123")
        KSafe("with_underscore")
        KSafe("data_v2")
    }

    /** Verifies filename validation rejects invalid characters */
    @Test
    fun filename_rejects_invalid() {
        assertFailsWith<IllegalArgumentException> { KSafe("UPPER") }
        assertFailsWith<IllegalArgumentException> { KSafe("") }
        assertFailsWith<IllegalArgumentException> { KSafe("123abc") } // must start with letter
        assertFailsWith<IllegalArgumentException> { KSafe("_leading") } // must start with letter
        assertFailsWith<IllegalArgumentException> { KSafe("has.dot") }
        assertFailsWith<IllegalArgumentException> { KSafe("has/slash") }
        assertFailsWith<IllegalArgumentException> { KSafe("has space") }
    }

    // ---------- Isolation between file names ----------

    /** Verifies same keys in different files are isolated */
    @Test
    fun isolation_sameKeys_doNotLeakAcrossDifferentFiles() = runTest {
        val s1 = newStore()
        val s2 = newStore()
        val key = "shared"
        s1.put(key, "v1", KSafeWriteMode.Plain)
        s2.put(key, "v2", KSafeWriteMode.Plain)
        assertEquals("v1", s1.get(key, "x"))
        assertEquals("v2", s2.get(key, "x"))
    }

    // ---------- Encryption behavior ----------

    /** Verifies auto-detection finds encrypted data */
    @Test
    fun encryption_autoDetectionFindsEncryptedData() = runTest {
        val s = newStore()
        val k = "ek"
        s.put(k, "secret") // encrypted by default
        assertEquals("secret", s.get(k, "x")) // auto-detected
    }

    /** Verifies unencrypted data round-trip works correctly */
    @Test
    fun unencrypted_roundTrip() = runTest {
        val s = newStore()
        val k = "plain"
        s.put(k, "p", KSafeWriteMode.Plain)
        assertEquals("p", s.get(k, "x"))
    }

    // ---------- Flows ----------

    /** Verifies unencrypted Flow emits value changes */
    @Test
    fun flow_unencrypted_emitsChanges() = runTest {
        val s = newStore()
        val k = "f_plain"
        s.getFlow(k, "d").test {
            assertEquals("d", awaitItem())
            s.put(k, "a", KSafeWriteMode.Plain)
            assertEquals("a", awaitItem())
            s.put(k, "b", KSafeWriteMode.Plain)
            assertEquals("b", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    /** Verifies encrypted Flow emits value changes */
    @Test
    fun flow_encrypted_emitsChanges() = runTest {
        val s = newStore()
        val k = "f_enc"
        s.getFlow(k, 0).test {
            assertEquals(0, awaitItem())
            s.put(k, 1)
            assertEquals(1, awaitItem())
            s.put(k, 2)
            assertEquals(2, awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    // ---------- Delegates ----------

    /** Verifies delegate uses property name as key and encrypts by default */
    @Test
    fun delegate_defaultEncrypted_and_propertyNameKey() = runTest {
        val s = newStore()
        var secret: String by s(defaultValue = "init")
        assertEquals("init", secret)
        secret = "z"
        assertEquals("z", secret)
        assertEquals("z", s.get("secret", "x")) // auto-detected
    }

    /** Verifies delegate with explicit key and unencrypted mode */
    @Test
    fun delegate_explicitKey_unencrypted() = runTest {
    val s = newStore()
        var count: Int by s(defaultValue = 0, key = "count", mode = KSafeWriteMode.Plain)
        assertEquals(0, count)
        count = 3
        assertEquals(3, count)
        assertEquals(3, s.get("count", -1)) // auto-detected
    }

    // ---------- Types ----------

    /** Verifies all primitive types work with unencrypted storage */
    @Test
    fun primitives_unencrypted_roundTrip() = runTest {
        val s = newStore()
        s.put("i", 1, KSafeWriteMode.Plain); assertEquals(1, s.get("i", 0))
        s.put("l", 2L, KSafeWriteMode.Plain); assertEquals(2L, s.get("l", 0L))
        s.put("f", 1.5f, KSafeWriteMode.Plain); assertEquals(1.5f, s.get("f", 0f))
        s.put("d", 2.5, KSafeWriteMode.Plain); assertEquals(2.5, s.get("d", 0.0))
        s.put("b", true, KSafeWriteMode.Plain); assertEquals(true, s.get("b", false))
        s.put("s", "hi", KSafeWriteMode.Plain); assertEquals("hi", s.get("s", "x"))
    }

    @Serializable
    data class Person(val id: Long, val name: String)

    /** Verifies @Serializable objects work with encrypted storage */
    @Test
    fun serializable_encrypted_roundTrip() = runTest {
        val s = newStore()
        val k = "person"
        val p = Person(7, "Grace")
        s.put(k, p) // encrypted
        assertEquals(p, s.get(k, Person(0, ""))) // auto-detected
    }

    // ---------- Delete ----------

    /** Verifies delete works for both plain and encrypted values */
    @Test
    fun delete_plain_and_encrypted() = runTest {
        val s = newStore()
        val kp = "plainDel"; val ke = "encDel"
        s.put(kp, "p", KSafeWriteMode.Plain); s.put(ke, "e")
        s.delete(kp); s.delete(ke)
        assertEquals("x", s.get(kp, "x"))
        assertEquals("x", s.get(ke, "x"))
    }

    // ---------- Composition ----------

    class Prefs(private val s: KSafe) {
        var theme: String by s(defaultValue = "light", key = "theme", mode = KSafeWriteMode.Plain)
        var auth: String by s(defaultValue = "", key = "auth") // encrypted
        var level: Int by s(defaultValue = 0, key = "level", mode = KSafeWriteMode.Plain)
    }

    /** Verifies multiple KSafe instances with different files are isolated */
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

    /** Verifies delegate changes are visible via direct API */
    @Test
    fun composition_updates_visibleViaDirectAPI() = runTest {
        val s = newStore(); val p = Prefs(s)
        p.theme = "green"; p.auth = "tok"; p.level = 4
        assertEquals("green", s.get("theme", "x"))
        assertEquals("tok", s.get("auth", "x"))
        assertEquals(4, s.get("level", -1))
    }
}
