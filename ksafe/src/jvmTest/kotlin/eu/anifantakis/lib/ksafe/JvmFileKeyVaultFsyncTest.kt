package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertContentEquals

/**
 * Locks in: every mutating FileKeyVault write (put/delete) fsyncs the parent directory after the atomic rename, so a crash can't lose the rename and leave the sole master-key file missing.
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

        assertContentEquals(byteArrayOf(1, 2, 3), vault.get("alias"))

        val countAfterPut = syncedDirs.size
        vault.delete("alias")
        assertTrue(syncedDirs.size > countAfterPut, "delete (which rewrites the file) must also fsync the parent directory")
    }
}
