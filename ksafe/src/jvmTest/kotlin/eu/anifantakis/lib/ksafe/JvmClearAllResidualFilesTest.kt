package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: clearAll() also wipes residual JVM-fallback files holding recoverable secrets — the *.migrated archives (plaintext keys / ciphertext) and *.corrupt-<ts> copies — while sparing a different safe's residue in the same directory.
 */
class JvmClearAllResidualFilesTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_clr_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    @Test
    fun clearAll_deletesMigratedAndCorruptResidue_butSpareSiblingSafe() = runTest {
        val fileName = "residual"
        val base = "eu_anifantakis_ksafe_datastore_$fileName"

        // Residue a prior fallback / corruption pass would have left in the storage dir.
        val migratedJson = File(tmp, "$base.ksafe.json.migrated").apply { writeText("CIPHERTEXT") }
        val migratedKeys = File(tmp, "$base.ksafe-keys.json.migrated").apply { writeText("PLAINTEXT-AES-KEYS") }
        val corrupt = File(tmp, "$base.ksafe.json.corrupt-123").apply { writeText("CIPHERTEXT") }
        // A DIFFERENT safe in the same directory — its residue must NOT be touched.
        val siblingMigrated = File(tmp, "eu_anifantakis_ksafe_datastore_other.ksafe-keys.json.migrated")
            .apply { writeText("OTHER-SAFE-KEYS") }

        val ksafe = KSafe(fileName = fileName, baseDir = tmp, testEngine = FakeEncryption())
        ksafe.put("token", "secret")
        ksafe.clearAll()
        ksafe.close()

        assertFalse(migratedJson.exists(), "clearAll must delete the migrated ciphertext archive")
        assertFalse(migratedKeys.exists(), "clearAll must delete the migrated PLAINTEXT keys archive")
        assertFalse(corrupt.exists(), "clearAll must delete the corrupt-quarantine copy")
        assertTrue(siblingMigrated.exists(), "a different safe's residue in the same dir must be preserved")
    }

    @Test
    fun clearAll_deletesCrashLeftoverKeyTempFiles_butSpareSiblingSafe() = runTest {
        val fileName = "residualtmp"
        val base = "eu_anifantakis_ksafe_datastore_$fileName"

        // A FileKeyVault.write() killed before its atomic move leaves a `<keys>.<rand>.tmp`
        // orphan holding the full plaintext key map — clearAll() must wipe it too.
        val staleKeyTemp = File(tmp, "$base.ksafe-keys.json8481920.tmp").apply { writeText("PLAINTEXT-AES-KEYS") }
        // A DIFFERENT safe's temp orphan in the same dir must be spared.
        val siblingTemp = File(tmp, "eu_anifantakis_ksafe_datastore_other.ksafe-keys.json777.tmp")
            .apply { writeText("OTHER-SAFE-KEYS") }

        val ksafe = KSafe(fileName = fileName, baseDir = tmp, testEngine = FakeEncryption())
        ksafe.put("token", "secret")
        ksafe.clearAll()
        ksafe.close()

        assertFalse(staleKeyTemp.exists(), "clearAll must delete a crashed write's plaintext key temp file")
        assertTrue(siblingTemp.exists(), "a different safe's temp orphan in the same dir must be preserved")
    }
}
