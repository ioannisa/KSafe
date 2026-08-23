package eu.anifantakis.lib.ksafe

import app.cash.turbine.test
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStoreKeyVault
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlin.test.*
import kotlinx.serialization.Serializable
import java.nio.file.Files

/** Locks in: custom file-name behavior — validation, per-file isolation, encryption/auto-detection, flows, delegates, type support, and deletes. */
@OptIn(ExperimentalCoroutinesApi::class)
class JvmFileNameTest {

    companion object {
        private val testCounter = java.util.concurrent.atomic.AtomicInteger(0)

        // Timestamp prefix (base-26 letters, since KSafe only allows [a-z]+) makes names unique across runs.
        private val runId: String = numberToLetters(System.currentTimeMillis())

        private fun generateUniqueFileName(): String {
            val count = testCounter.incrementAndGet()
            return "fnrun${runId}test${numberToLetters(count.toLong())}"
        }

    }

    private fun newStore(): KSafe = KSafe(generateUniqueFileName())

    @Test
    fun filename_accepts_valid_names() {
        // These should not throw.
        KSafe("abc123")
        KSafe("with_underscore")
        KSafe("data_v2")
    }

    @Test
    fun baseDir_storesFileInProvidedDirectory() = runTest {
        val tmpDir = Files.createTempDirectory("tmpKsafeTest").toFile()
        try {
            val name = "temporary_ksafe"
            val safe = KSafe(fileName = name, baseDir = tmpDir)
            safe.put("hello", "world")

            val expected = java.io.File(tmpDir, "eu_anifantakis_ksafe_datastore_$name.preferences_pb")
            assertTrue(expected.exists(), "Expected $expected to exist")
            assertEquals(1, tmpDir.list()?.size ?: 0)

            assertEquals("world", safe.get("hello", "fallback"))
        } finally {
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun baseDir_clearAll_wipesAllDataInProvidedDirectory() = runTest {
        val tmpDir = Files.createTempDirectory("tmpKsafeClearTest").toFile()
        try {
            val name = "temporary_clear_ksafe"
            val safe = KSafe(fileName = name, baseDir = tmpDir)
            safe.put("k", "v")
            val storeFile = java.io.File(tmpDir, "eu_anifantakis_ksafe_datastore_$name.preferences_pb")
            assertTrue(storeFile.exists(), "Expected $storeFile to exist before clearAll()")

            // Capture the key material that exists BEFORE the wipe. That is what clearAll()
            // promises to destroy. It does NOT promise the store never holds a key record again:
            // every KSafeCore.init eagerly mints both masters off-thread (prewarmMasterKeys), and
            // in jvmTest the software fallback keeps key records in this very file — so asserting
            // "no ksafe_key_ prefix anywhere afterwards" is a race against an unrelated mint, not
            // a wipe check. Assert the specific pre-clear bytes are gone instead.
            val preClearKeyMaterial = safe.dataStore.data.first().asMap()
                .filterKeys { it.name.startsWith(DataStoreKeyVault.KEY_PREFIX) }
                .values.map { it.toString() }
            assertTrue(
                preClearKeyMaterial.isNotEmpty(),
                "the software fallback must have persisted a key record before clearAll()",
            )

            safe.clearAll()

            // clearAll() guarantees no RECOVERABLE data remains — not that the physical file is
            // gone. The live DataStore file is intentionally NOT deleted out-of-band: a raw
            // File.delete() on the caller thread races a concurrent consumer write (e.g. a key
            // mint during a rotation) and can strand a just-persisted record, leaving an in-RAM-
            // only key that is unreadable after restart. storage.clear() already emptied it; an
            // empty preferences file holds no ciphertext and no key material.
            assertEquals("default", safe.get("k", "default"), "the value must be wiped")
            val reopened = KSafe(fileName = name, baseDir = tmpDir)
            assertEquals("default", reopened.get("k", "default"), "the wipe must survive a cold reopen")
            reopened.close()

            // No pre-clear key material and no ciphertext survives in the on-disk store.
            val residue = if (storeFile.exists()) storeFile.readBytes().decodeToString() else ""
            for (keyMaterial in preClearKeyMaterial) {
                assertFalse(
                    residue.contains(keyMaterial),
                    "the key that could decrypt pre-clearAll data must not survive clearAll()",
                )
            }
            assertFalse(residue.contains("__ksafe_value_"), "no encrypted values may survive clearAll()")
            safe.close()
        } finally {
            tmpDir.deleteRecursively()
        }
    }

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

    @Test
    fun encryption_autoDetectionFindsEncryptedData() = runTest {
        val s = newStore()
        val k = "ek"
        s.put(k, "secret") // encrypted by default
        assertEquals("secret", s.get(k, "x")) // auto-detected
    }

    @Test
    fun unencrypted_roundTrip() = runTest {
        val s = newStore()
        val k = "plain"
        s.put(k, "p", KSafeWriteMode.Plain)
        assertEquals("p", s.get(k, "x"))
    }

    @Test
    fun flow_unencrypted_emitsChanges() = runTest {
        val s = newStore()
        val k = "f_plain"
        s.getFlow(k, "d").test(timeout = 30.seconds) {
            assertEquals("d", awaitItem())
            s.put(k, "a", KSafeWriteMode.Plain)
            assertEquals("a", awaitItem())
            s.put(k, "b", KSafeWriteMode.Plain)
            assertEquals("b", awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun flow_encrypted_emitsChanges() = runTest {
        val s = newStore()
        val k = "f_enc"
        s.getFlow(k, 0).test(timeout = 30.seconds) {
            assertEquals(0, awaitItem())
            s.put(k, 1)
            assertEquals(1, awaitItem())
            s.put(k, 2)
            assertEquals(2, awaitItem())
            cancelAndIgnoreRemainingEvents()
        }
    }

    @Test
    fun delegate_defaultEncrypted_and_propertyNameKey() = runTest {
        val s = newStore()
        var secret: String by s(defaultValue = "init")
        assertEquals("init", secret)
        secret = "z"
        assertEquals("z", secret)
        assertEquals("z", s.get("secret", "x")) // auto-detected
    }

    @Test
    fun delegate_explicitKey_unencrypted() = runTest {
    val s = newStore()
        var count: Int by s(defaultValue = 0, key = "count", mode = KSafeWriteMode.Plain)
        assertEquals(0, count)
        count = 3
        assertEquals(3, count)
        assertEquals(3, s.get("count", -1)) // auto-detected
    }

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

    @Test
    fun serializable_encrypted_roundTrip() = runTest {
        val s = newStore()
        val k = "person"
        val p = Person(7, "Grace")
        s.put(k, p) // encrypted
        assertEquals(p, s.get(k, Person(0, ""))) // auto-detected
    }

    @Test
    fun delete_plain_and_encrypted() = runTest {
        val s = newStore()
        val kp = "plainDel"; val ke = "encDel"
        s.put(kp, "p", KSafeWriteMode.Plain); s.put(ke, "e")
        s.delete(kp); s.delete(ke)
        assertEquals("x", s.get(kp, "x"))
        assertEquals("x", s.get(ke, "x"))
    }

    class Prefs(private val s: KSafe) {
        var theme: String by s(defaultValue = "light", key = "theme", mode = KSafeWriteMode.Plain)
        var auth: String by s(defaultValue = "", key = "auth") // encrypted
        var level: Int by s(defaultValue = 0, key = "level", mode = KSafeWriteMode.Plain)
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
        assertEquals("green", s.get("theme", "x"))
        assertEquals("tok", s.get("auth", "x"))
        assertEquals(4, s.get("level", -1))
    }
}
