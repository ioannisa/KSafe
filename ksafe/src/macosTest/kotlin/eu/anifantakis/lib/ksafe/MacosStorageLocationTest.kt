package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi

/**
 * macOS coverage for the storage-location code paths in
 * [KSafe] (Apple factory):
 *
 *  1. `directory = ...` routes the DataStore file into the caller-supplied path.
 *  2. The `directory` parameter creates the directory if it doesn't exist
 *     (including any missing parents).
 *  3. The 1.x → 2.0 NSDocumentDirectory auto-migration is a no-op on macOS
 *     when no legacy file exists.
 *
 * Unlike the iOS variant, every test here writes inside [NSTemporaryDirectory]
 * via [MacosTestPaths] — never `~/Library/Application Support/`, which is
 * persistent and shared on a real Mac.
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalUuidApi::class)
class MacosStorageLocationTest {

    private val createdDirs = mutableListOf<String>()

    @AfterTest
    fun cleanup() {
        createdDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        createdDirs.clear()
    }

    /** `directory = ...` routes the DataStore file into the caller-supplied path. */
    @Test
    fun directory_storesFileInProvidedDirectory() = runTest {
        val name = MacosTestPaths.uniqueFileName("macosdir")
        val tmpRoot = MacosTestPaths.uniqueTempDir("macos-storage-test")
        createdDirs += tmpRoot

        val safe = KSafe(
            fileName = name,
            directory = tmpRoot,
            testEngine = FakeEncryption(),
        )
        safe.put("hello", "world")

        val expectedPath = "$tmpRoot/eu_anifantakis_ksafe_datastore_$name.preferences_pb"
        assertTrue(
            MacosTestPaths.fileExists(expectedPath),
            "Expected DataStore file at $expectedPath",
        )
        assertEquals("world", safe.get("hello", "fallback"))
        safe.close()
    }

    /**
     * The factory creates the directory (and missing parents) when the path
     * doesn't exist yet. Real callers on macOS often want a child like
     * `~/Library/Application Support/<bundleId>/secrets/` and shouldn't need
     * to mkdir it themselves.
     */
    @Test
    fun directory_createsMissingParentDirectories() = runTest {
        val name = MacosTestPaths.uniqueFileName("macosmkdir")
        val tmpRoot = MacosTestPaths.uniqueTempDir("macos-storage-mkdir")
        createdDirs += tmpRoot
        val nestedPath = "$tmpRoot/level1/level2/level3"
        assertFalse(
            MacosTestPaths.fileExists(nestedPath),
            "Setup: nested directory should not exist before factory call",
        )

        val safe = KSafe(
            fileName = name,
            directory = nestedPath,
            testEngine = FakeEncryption(),
        )
        safe.put("hello", "nested")

        assertTrue(
            MacosTestPaths.fileExists(nestedPath),
            "Factory should have created the nested directory hierarchy",
        )
        val expectedPath = "$nestedPath/eu_anifantakis_ksafe_datastore_$name.preferences_pb"
        assertTrue(
            MacosTestPaths.fileExists(expectedPath),
            "DataStore file should exist inside the freshly-created directory",
        )
        safe.close()
    }

    /**
     * The 1.x → 2.0 auto-migration looks for a legacy file at
     * `NSDocumentDirectory/<basename>.preferences_pb`. On macOS the user's
     * `~/Documents` folder is real and shared, so we deliberately do NOT
     * plant a fake legacy file here. Instead we verify the migration path
     * is a *safe no-op*: with `directory = <temp>`, the legacy lookup is
     * skipped entirely (per the factory contract — legacy migration runs
     * only when `directory == null`), and writes still land at the
     * provided path.
     */
    @Test
    fun explicitDirectory_skipsLegacyMigrationCheck() = runTest {
        val name = MacosTestPaths.uniqueFileName("macosskipmig")
        val customDir = MacosTestPaths.uniqueTempDir("macos-skipmig")
        createdDirs += customDir

        val safe = KSafe(
            fileName = name,
            directory = customDir,
            testEngine = FakeEncryption(),
        )
        safe.put("k", "v")

        val expectedPath = "$customDir/eu_anifantakis_ksafe_datastore_$name.preferences_pb"
        assertTrue(
            MacosTestPaths.fileExists(expectedPath),
            "Factory should write at the explicit directory regardless of legacy state",
        )
        assertEquals("v", safe.get("k", "fallback"))
        safe.close()
    }

    /** Write, close, re-open at the same explicit directory and read back. */
    @Test
    fun directoryOverride_persistsAcrossInstances() = runTest {
        val name = MacosTestPaths.uniqueFileName("macospersist")
        val tmpRoot = MacosTestPaths.uniqueTempDir("macos-persist")
        createdDirs += tmpRoot

        run {
            val first = KSafe(
                fileName = name,
                directory = tmpRoot,
                testEngine = FakeEncryption(),
            )
            first.put("persist", "yes")
            first.close()
        }

        val second = KSafe(
            fileName = name,
            directory = tmpRoot,
            testEngine = FakeEncryption(),
        )
        assertEquals("yes", second.get("persist", "no"))
        second.close()

        // Sanity check that the original file still exists at the expected path
        val expectedPath = "$tmpRoot/eu_anifantakis_ksafe_datastore_$name.preferences_pb"
        assertTrue(
            MacosTestPaths.fileExists(expectedPath),
            "DataStore file must survive the close/reopen cycle",
        )
    }
}
