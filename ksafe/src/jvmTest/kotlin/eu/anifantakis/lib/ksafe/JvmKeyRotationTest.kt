package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in rotateKeys() (3.0.0): every encrypted entry is re-encrypted under a fresh key
 * generation, values keep reading back (same instance AND across a cold reopen), superseded
 * keys are deleted once unreferenced, new writes mint under the new generation, and a
 * concurrent user write is never clobbered by the rotation.
 *
 * FakeEncryption derives its XOR key from the alias string, so decrypting under the wrong
 * generation's alias yields garbage — a read that survives rotation proves the alias
 * bookkeeping end to end.
 */
class JvmKeyRotationTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_rot_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    private fun newKSafe(fileName: String, engine: FakeEncryption) =
        KSafe(fileName = fileName, baseDir = tmp, testEngine = engine)

    @Test
    fun rotateKeys_reEncryptsEverything_valuesStillRead_andOldKeysAreSwept() = runTest {
        val engine = FakeEncryption()
        val ksafe = newKSafe("rot_basic", engine)

        ksafe.put("token", "secret-token")
        ksafe.put("pin", 4711)
        ksafe.put("hw", "isolated", KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
        ksafe.put("plain", "not-encrypted", KSafeWriteMode.Plain)

        val generation1Aliases = engine.encryptedKeys.toSet()
        assertTrue(generation1Aliases.none { it.endsWith(".g2") }, "before rotation everything is base generation")

        val result = ksafe.rotateKeys()

        assertEquals(3, result.rotated, "the three ENCRYPTED entries rotate; the plain one has no key")
        assertEquals(0, result.skipped)
        assertEquals(0, result.failed)
        assertEquals(2, result.keyGeneration)

        // Every value still reads back after the rotation.
        assertEquals("secret-token", ksafe.get("token", ""))
        assertEquals(4711, ksafe.get("pin", 0))
        assertEquals("isolated", ksafe.get("hw", ""))
        assertEquals("not-encrypted", ksafe.get("plain", ""))

        // The re-encrypts happened under generation-2 aliases...
        assertTrue(engine.encryptedKeys.any { it.endsWith(".g2") }, "rotation must mint .g2 aliases")
        // ...and every generation-1 alias was deleted (fully-rotated store references nothing old).
        for (alias in generation1Aliases) {
            assertTrue(alias in engine.deletedKeys, "superseded generation-1 key '$alias' must be deleted")
        }

        ksafe.close()
    }

    @Test
    fun rotatedValues_surviveAColdReopen() = runTest {
        val fileName = "rot_reopen"
        val first = newKSafe(fileName, FakeEncryption())
        first.put("token", "persisted-secret")
        first.rotateKeys()
        first.close()

        // Fresh instance + fresh engine (FakeEncryption keys are derived from the alias, so a
        // reopen decrypts iff the recorded generation resolves to the SAME alias).
        val reopened = newKSafe(fileName, FakeEncryption())
        assertEquals("persisted-secret", reopened.get("token", ""), "a rotated entry must decrypt after reopen")
        reopened.close()
    }

    @Test
    fun newWrites_afterRotation_useTheNewGeneration_andRotationsStack() = runTest {
        val engine = FakeEncryption()
        val ksafe = newKSafe("rot_stack", engine)

        ksafe.put("a", "one")
        assertEquals(2, ksafe.rotateKeys().keyGeneration)

        engine.encryptedKeys.clear()
        ksafe.put("b", "two")
        assertTrue(
            engine.encryptedKeys.all { it.endsWith(".g2") },
            "a write after rotation must encrypt under the new generation, got ${engine.encryptedKeys}",
        )

        val second = ksafe.rotateKeys()
        assertEquals(3, second.keyGeneration)
        assertEquals(2, second.rotated, "both entries re-rotate to generation 3")
        assertEquals("one", ksafe.get("a", ""))
        assertEquals("two", ksafe.get("b", ""))

        ksafe.close()
    }

    @Test
    fun aConcurrentWrite_isNeverClobberedByRotation() = runTest {
        val ksafe = newKSafe("rot_race", FakeEncryption())
        ksafe.put("counter", "before")

        // Whichever order the consumer serializes them in, the user write must win:
        // rotate-then-put overwrites under the new generation; put-then-rotate makes the
        // rotation's CAS skip the superseded snapshot.
        coroutineScope {
            val rot = async { ksafe.rotateKeys() }
            ksafe.put("counter", "user-write-wins")
            rot.await()
        }

        assertEquals("user-write-wins", ksafe.get("counter", ""))
        ksafe.close()
    }

    @Test
    fun getOrCreateSecret_keepsItsValueAcrossRotation() = runTest {
        val ksafe = newKSafe("rot_secret", FakeEncryption())
        val before = ksafe.getOrCreateSecret("db.pass", 32)
        ksafe.rotateKeys()
        val after = ksafe.getOrCreateSecret("db.pass", 32)
        assertTrue(before.contentEquals(after), "rotation must never change a secret's VALUE, only its envelope")
        ksafe.close()
    }

    @Test
    fun rotation_isANoOp_onAStoreWithNoEncryptedEntries() = runTest {
        val ksafe = newKSafe("rot_empty", FakeEncryption())
        ksafe.put("plain", "x", KSafeWriteMode.Plain)
        val result = ksafe.rotateKeys()
        assertEquals(0, result.rotated)
        assertEquals(0, result.failed)
        assertEquals(2, result.keyGeneration, "the generation still advances so new writes get fresh keys")
        assertEquals("x", ksafe.get("plain", ""))
        ksafe.close()
    }
}
