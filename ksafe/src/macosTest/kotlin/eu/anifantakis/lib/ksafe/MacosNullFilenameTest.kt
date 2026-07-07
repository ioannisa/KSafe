package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: with `fileName = null` KSafe uses the bare `eu_anifantakis_ksafe_datastore`
 * basename (no `_<name>` suffix) and still works on macOS. Pinned to a temp directory so
 * it never touches the shared `NSApplicationSupportDirectory` location.
 */
@OptIn(ExperimentalForeignApi::class)
class MacosNullFilenameTest {

    private val createdDirs = mutableListOf<String>()

    @AfterTest
    fun cleanup() {
        createdDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        createdDirs.clear()
    }

    @Test
    fun testWithNullFilename() = runTest {
        val tempDir = MacosTestPaths.uniqueTempDir("macos-nullname")
        createdDirs += tempDir

        val ksafe = KSafe(
            fileName = null,
            directory = tempDir,
            testEngine = FakeEncryption(),
        )

        val key = "test_key"
        val value = "test_value"

        ksafe.put(key, value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get(key, "default"))

        val expectedPath = "$tempDir/eu_anifantakis_ksafe_datastore.preferences_pb"
        assertTrue(
            MacosTestPaths.fileExists(expectedPath),
            "Default-named DataStore should land at $expectedPath",
        )
        ksafe.close()
    }
}
