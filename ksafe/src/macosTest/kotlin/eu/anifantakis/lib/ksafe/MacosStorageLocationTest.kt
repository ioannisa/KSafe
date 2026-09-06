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
 * Locks in: the macOS storage-location paths — an explicit `directory` routes the DataStore file
 * there, creates the missing parents, and skips the 1.x legacy lookup. Unlike the iOS variant every
 * test writes inside [NSTemporaryDirectory] via [MacosTestPaths]: `~/Library/Application Support/`
 * is persistent and shared on a real Mac.
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalUuidApi::class)
class MacosStorageLocationTest {

    private val createdDirs = mutableListOf<String>()

    @AfterTest
    fun cleanup() {
        createdDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        createdDirs.clear()
    }

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
     * Real callers want a child like `~/Library/Application Support/<bundleId>/secrets/` and
     * shouldn't have to mkdir it themselves.
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
     * A real user's `~/Documents` is not somewhere to plant a fake legacy file, so this checks the
     * safe half: an explicit `directory` skips the legacy lookup and the write lands there anyway.
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

        val expectedPath = "$tmpRoot/eu_anifantakis_ksafe_datastore_$name.preferences_pb"
        assertTrue(
            MacosTestPaths.fileExists(expectedPath),
            "DataStore file must survive the close/reopen cycle",
        )
    }
}
