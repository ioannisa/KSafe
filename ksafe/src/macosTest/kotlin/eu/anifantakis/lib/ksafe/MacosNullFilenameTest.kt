package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * macOS coverage for KSafe with `fileName = null` — the default-named
 * DataStore code path.
 *
 * Unlike [IosNullFilenameTest], this test never touches the default
 * `NSApplicationSupportDirectory` location: every instance is pinned to a
 * temp directory via `directory = ...`. The point is to verify that the
 * "no fileName" branch (which uses the bare `eu_anifantakis_ksafe_datastore`
 * basename without the `_<name>` suffix) still produces a working KSafe
 * on macOS.
 */
@OptIn(ExperimentalForeignApi::class)
class MacosNullFilenameTest {

    private val createdDirs = mutableListOf<String>()

    @AfterTest
    fun cleanup() {
        createdDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        createdDirs.clear()
    }

    /** Verifies KSafe works with null filename (uses default basename). */
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

        // The default basename has no `_<name>` suffix.
        val expectedPath = "$tempDir/eu_anifantakis_ksafe_datastore.preferences_pb"
        assertTrue(
            MacosTestPaths.fileExists(expectedPath),
            "Default-named DataStore should land at $expectedPath",
        )
        ksafe.close()
    }
}
