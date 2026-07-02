package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertContentEquals

/**
 * FEEDBACK_4 low: [FileKeyVault] holds the ONLY copy of the software master AES key.
 * It fsyncs the temp file's data before an atomic rename, but a crash right after the
 * rename could still lose the rename (a directory-entry change) — leaving the key file
 * missing, indistinguishable from "no keys yet", which the startup orphan sweep treats
 * as "delete every encrypted entry". The write must therefore also fsync the PARENT
 * DIRECTORY after the move. Crash durability can't be simulated in a unit test, so this
 * verifies the parent-dir fsync is actually performed on every mutating write.
 */
class JvmFileKeyVaultFsyncTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_fkv_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest
    fun tearDown() { tmp.deleteRecursively() }

    @Test
    fun put_and_delete_fsyncTheParentDirectory() {
        val file = File(tmp, "vault.ksafe-keys.json")
        val syncedDirs = mutableListOf<File>()
        val vault = FileKeyVault(file, syncDir = { syncedDirs.add(it) })

        vault.put("alias", byteArrayOf(1, 2, 3))
        assertTrue(syncedDirs.isNotEmpty(), "put must fsync the parent directory after the atomic rename")
        assertEquals(tmp.absoluteFile, syncedDirs.last(), "the fsynced directory must be the key file's parent")

        // The write still works end-to-end.
        assertContentEquals(byteArrayOf(1, 2, 3), vault.get("alias"))

        val countAfterPut = syncedDirs.size
        vault.delete("alias")
        assertTrue(syncedDirs.size > countAfterPut, "delete (which rewrites the file) must also fsync the parent directory")
    }
}
