package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * End-to-end regression guard for the per-entry alias namespace, using an engine with REAL
 * key-lifecycle semantics ([StatefulFakeEncryption]): with the plain `.gN` suffix, rotating
 * a store holding both `"foo"` and `"foo.g2"` reused/deleted one entry's vault key for the
 * other (silent, unrecoverable loss for hardware-isolated data), and `delete()`/`clearAll()`
 * issued engine-key deletions for entries that never owned a per-entry alias — deletions
 * whose derived alias can be another store's live key.
 */
class JvmAliasCollisionTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_acol_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    private val hwi = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)

    @Test
    fun dottedGenerationTwin_survivesRotation_andSiblingDelete() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(fileName = "acol", baseDir = tmp, testEngine = engine)
        ksafe.put("foo", "foo-secret", hwi)
        ksafe.put("foo.g2", "twin-secret", hwi)

        val result = ksafe.rotateKeys()
        assertEquals(2, result.rotated)
        assertEquals(0, result.failed)

        // Pre-fix, "foo"'s rotated alias was byte-identical to "foo.g2"'s live generation-1
        // alias: rotating both in one pass deleted the shared key under the freshly-rotated
        // ciphertext while still counting it as rotated.
        assertEquals("foo-secret", ksafe.get("foo", ""), "rotated entry must stay readable")
        assertEquals("twin-secret", ksafe.get("foo.g2", ""), "its .g2-named sibling must stay readable")

        // Pre-fix, delete("foo") swept alias generations 1..2, and its g2 alias WAS the
        // sibling's bare alias — destroying the sibling's key.
        ksafe.delete("foo")
        assertEquals("twin-secret", ksafe.get("foo.g2", ""), "deleting 'foo' must not destroy 'foo.g2'")
        ksafe.close()

        // Cold reopen over the same engine state: nothing was served from RAM.
        val reopened = KSafe(fileName = "acol", baseDir = tmp, testEngine = engine)
        assertEquals("twin-secret", reopened.get("foo.g2", ""), "sibling must decrypt after cold reopen")
        assertEquals("", reopened.get("foo", ""), "the deleted entry reads its default")
        reopened.close()
    }

    @Test
    fun deleteOfPlainDefaultOrAbsentKeys_issuesNoPerEntryKeyDeletion() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(fileName = "acolgate", baseDir = tmp, testEngine = engine)
        ksafe.put("plain.key", "v", KSafeWriteMode.Plain)
        ksafe.put("default.key", "v") // v2 DEFAULT rides the master alias

        ksafe.delete("plain.key")
        ksafe.delete("default.key")
        ksafe.delete("absent.key")

        // None of the three ever owned a per-entry alias; issuing the delete anyway would
        // destroy a sibling store's live key when the derived alias collides.
        assertTrue(
            engine.deletedKeys.none { alias ->
                "plain.key" in alias || "default.key" in alias || "absent.key" in alias
            },
            "no per-entry engine deletion may be issued for plain/master-riding/absent keys, got ${engine.deletedKeys}",
        )
        ksafe.close()
    }

    @Test
    fun deleteOfHardwareIsolatedKey_stillSweepsItsOwnAlias() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(fileName = "acolhwi", baseDir = tmp, testEngine = engine)
        ksafe.put("hw", "v", hwi)
        ksafe.delete("hw")
        assertTrue(
            engine.deletedKeys.any { "hw" in it },
            "a HARDWARE_ISOLATED entry's own alias must still be reclaimed, got ${engine.deletedKeys}",
        )
        ksafe.close()
    }

    @Test
    fun clearAll_sweepsOnlyOwnedPerEntryAliases_notDefaultDottedOnes() = runTest {
        val engine = StatefulFakeEncryption()
        val ksafe = KSafe(fileName = "acolclear", baseDir = tmp, testEngine = engine)
        ksafe.put("vault.token", "v") // DEFAULT — master-riding; its derived per-entry
        ksafe.put("hw", "v", hwi)     // alias could be a named store's live key
        ksafe.clearAll()

        assertTrue(
            engine.deletedKeys.none { it.endsWith("vault.token") },
            "clearAll must not issue a per-entry deletion for a master-riding DEFAULT entry, got ${engine.deletedKeys}",
        )
        assertTrue(
            engine.deletedKeys.any { "hw" in it },
            "clearAll must still reclaim owned HARDWARE_ISOLATED aliases, got ${engine.deletedKeys}",
        )
        assertTrue(
            engine.deletedKeys.any { "__ksafe_master__" in it },
            "clearAll must still drop the master keys, got ${engine.deletedKeys}",
        )
        ksafe.close()
    }
}
