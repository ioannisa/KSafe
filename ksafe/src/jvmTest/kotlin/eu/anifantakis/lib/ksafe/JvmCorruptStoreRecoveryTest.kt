package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A corrupt DataStore `.preferences_pb` must not throw `CorruptionException`
 * on every read forever — that would crash the background collector and make
 * `getDirect` silently return defaults while suspend `get()` throws. The
 * factory installs a corruption handler that quarantines the unreadable file
 * and continues from an empty store (matching the JSON-fallback backend).
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

        // Construct (lazyLoad=false → the collector reads the store at startup,
        // hitting the corruption immediately).
        val ksafe = KSafe(fileName = fileName, baseDir = tmp, testEngine = FakeEncryption())
        try {
            // Read returns the default rather than crashing.
            assertEquals("def", ksafe.getDirect("anything", "def"))

            // The store recovered to empty — a fresh write round-trips.
            ksafe.put("k", "v")
            assertEquals("v", ksafe.get("k", "none"), "store must be usable again after corruption recovery")

            // The corrupt bytes were quarantined for recovery, not silently discarded.
            val quarantined = tmp.listFiles()?.any { it.name.contains(".preferences_pb.corrupt-") } == true
            assertTrue(quarantined, "the corrupt file must be copied aside (.corrupt-*) for recovery")
        } finally {
            ksafe.close()
        }
    }
}
