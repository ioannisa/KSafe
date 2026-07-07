package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: a corrupt DataStore .preferences_pb is quarantined and recovered to an empty store instead of throwing CorruptionException on every read, so the store stays usable.
 */
class JvmCorruptStoreRecoveryTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_corrupt_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    @Test
    fun corruptPreferencesFile_recoversToEmpty_quarantinesFile_doesNotCrash() = runTest {
        val fileName = "corrupt"
        val pb = File(tmp, "eu_anifantakis_ksafe_datastore_$fileName.preferences_pb")
        // Garbage that the DataStore Preferences (protobuf) reader can't parse → CorruptionException.
        pb.writeBytes(ByteArray(64) { 0xFF.toByte() })

        // lazyLoad=false → the collector reads the store at startup, hitting the corruption immediately.
        val ksafe = KSafe(fileName = fileName, baseDir = tmp, testEngine = FakeEncryption())
        try {
            assertEquals("def", ksafe.getDirect("anything", "def"))

            ksafe.put("k", "v")
            assertEquals("v", ksafe.get("k", "none"), "store must be usable again after corruption recovery")

            val quarantined = tmp.listFiles()?.any { it.name.contains(".preferences_pb.corrupt-") } == true
            assertTrue(quarantined, "the corrupt file must be copied aside (.corrupt-*) for recovery")
        } finally {
            ksafe.close()
        }
    }
}
