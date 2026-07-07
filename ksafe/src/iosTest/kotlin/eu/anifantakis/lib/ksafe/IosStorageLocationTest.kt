package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.test.runTest
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSData
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.NSThread
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.NSUserDomainMask
import platform.Foundation.create
import platform.Foundation.dataUsingEncoding
import platform.Foundation.writeToFile
import kotlin.concurrent.AtomicInt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * iOS-specific tests for the new 2.0 storage-location behaviour:
 *
 *  1. The `directory` parameter routes the DataStore into a caller-supplied path.
 *  2. The 1.x → 2.0 auto-migration relocates a legacy file from
 *     `NSDocumentDirectory` to `NSApplicationSupportDirectory` on first launch.
 *  3. An explicit `directory` override skips the legacy migration.
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalUuidApi::class)
class IosStorageLocationTest {

    companion object {
        private val counter = AtomicInt(0)

        /** Fresh, lowercase, KSafe-regex-valid filename per test invocation. */
        private fun uniqueFileName(prefix: String): String {
            val salt = (counter.incrementAndGet()).toString(36)
                .filter { it in 'a'..'z' || it in '0'..'9' }
                .ifEmpty { "x" }
            val uuid = Uuid.random().toString().lowercase().filter { it in 'a'..'z' }.take(8)
            return "${prefix}_${salt}_$uuid"
        }

        @OptIn(ExperimentalForeignApi::class)
        private fun documentsDirPath(): String =
            requireNotNull(
                NSFileManager.defaultManager.URLForDirectory(
                    directory = NSDocumentDirectory,
                    inDomain = NSUserDomainMask,
                    appropriateForURL = null,
                    create = true,
                    error = null,
                )
            ) { "Could not locate NSDocumentDirectory" }.path
                ?: error("NSDocumentDirectory has no path")

        @OptIn(ExperimentalForeignApi::class)
        private fun applicationSupportDirPath(): String =
            requireNotNull(
                NSFileManager.defaultManager.URLForDirectory(
                    directory = NSApplicationSupportDirectory,
                    inDomain = NSUserDomainMask,
                    appropriateForURL = null,
                    create = true,
                    error = null,
                )
            ) { "Could not locate NSApplicationSupportDirectory" }.path
                ?: error("NSApplicationSupportDirectory has no path")

        @OptIn(ExperimentalForeignApi::class)
        private fun fileExists(path: String): Boolean =
            NSFileManager.defaultManager.fileExistsAtPath(path)

        @OptIn(ExperimentalForeignApi::class)
        private fun deleteFileIfExists(path: String) {
            if (fileExists(path)) {
                NSFileManager.defaultManager.removeItemAtPath(path, error = null)
            }
        }

        @OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
        private fun writeBytesAt(path: String, contents: String) {
            val data: NSData = (NSString.create(string = contents))
                .dataUsingEncoding(NSUTF8StringEncoding)!!
            data.writeToFile(path, atomically = true)
        }
    }

    /** `directory = ...` routes the DataStore file into the caller-supplied path. */
    @Test
    fun directory_storesFileInProvidedDirectory() = runTest {
        val name = uniqueFileName("iosdir")
        val tmpRoot = applicationSupportDirPath() + "/ksafe_iostest_" + name
        NSFileManager.defaultManager.createDirectoryAtPath(
            tmpRoot,
            withIntermediateDirectories = true,
            attributes = null,
            error = null,
        )

        try {
            val safe = KSafe(
                fileName = name,
                directory = tmpRoot,
                testEngine = FakeEncryption(),
            )
            safe.put("hello", "world")

            val expectedPath = "$tmpRoot/eu_anifantakis_ksafe_datastore_$name.preferences_pb"
            assertTrue(fileExists(expectedPath), "Expected $expectedPath to exist")

            // Roundtrip — confirms the DataStore is actually backed by that file
            assertEquals("world", safe.get("hello", "fallback"))
        } finally {
            NSFileManager.defaultManager.removeItemAtPath(tmpRoot, error = null)
        }
    }

    /**
     * 1.x → 2.0 auto-migration: when `directory == null` and the new
     * NSApplicationSupportDirectory location is empty, a legacy file at the
     * old NSDocumentDirectory path is relocated on KSafe construction.
     */
    @Test
    fun legacyDocumentsFile_isMigratedToApplicationSupport() = runTest {
        val name = uniqueFileName("iosmig")
        val baseFileName = "eu_anifantakis_ksafe_datastore_$name"
        val legacyPath = "${documentsDirPath()}/$baseFileName.preferences_pb"
        val newPath = "${applicationSupportDirPath()}/$baseFileName.preferences_pb"

        // Defensive cleanup in case a prior failed run left state behind.
        deleteFileIfExists(legacyPath)
        deleteFileIfExists(newPath)

        try {
            // Simulate a 1.x install: legacy file present, new location empty.
            writeBytesAt(legacyPath, "legacy-1x-content")
            assertTrue(fileExists(legacyPath), "Setup: legacy file should exist before migration")
            assertFalse(fileExists(newPath), "Setup: new path should be empty before migration")

            // Construct KSafe with default `directory = null` → migration runs.
            KSafe(fileName = name, testEngine = FakeEncryption())

            assertFalse(fileExists(legacyPath), "Legacy file should have been moved away")
            assertTrue(fileExists(newPath), "File should have been moved to NSApplicationSupportDirectory")
        } finally {
            deleteFileIfExists(legacyPath)
            deleteFileIfExists(newPath)
        }
    }

    /**
     * Locks in: data written at the legacy `NSDocumentDirectory` path is still
     * readable after the 1.x → 2.0 auto-migration moves the file to
     * `NSApplicationSupportDirectory`.
     */
    @Test
    fun legacyDocumentsFile_dataIsReadableAfterMigration() = runTest {
        val name = uniqueFileName("iosmigdata")
        val baseFileName = "eu_anifantakis_ksafe_datastore_$name"
        val legacyPath = "${documentsDirPath()}/$baseFileName.preferences_pb"
        val newPath = "${applicationSupportDirPath()}/$baseFileName.preferences_pb"

        deleteFileIfExists(legacyPath)
        deleteFileIfExists(newPath)

        try {
            // Simulate a 1.x install: write a real DataStore file at
            // NSDocumentDirectory through KSafe itself. FakeEncryption is
            // deterministic across instances, so a later instance can decrypt it.
            val v1Like = KSafe(
                fileName = name,
                directory = documentsDirPath(),
                testEngine = FakeEncryption(),
            )
            v1Like.put("plain_key", "plain_value")
            v1Like.put("encrypted_key", "encrypted_value", KSafeWriteMode.Encrypted())
            v1Like.close()

            // Durability barrier: close() does not flush DataStore, so poll the
            // semantic invariant — a throwaway reader pinned to the legacy dir
            // (directory != null ⇒ no migration) must read both values back.
            // NSThread real-sleep because runTest's virtual clock skips kotlinx delay.
            var durable = false
            var attempt = 0
            while (!durable && attempt < 80) {            // ~8s floor; longer if a reacquire blocks
                attempt++
                // Reopening the same file back-to-back can transiently throw
                // "multiple DataStores active for the same file"; treat it as
                // not-ready and retry rather than failing on the flake.
                var probe: KSafe? = null
                durable = try {
                    probe = KSafe(
                        fileName = name,
                        directory = documentsDirPath(),
                        testEngine = FakeEncryption(),
                    )
                    probe.get("plain_key", "∅") == "plain_value" &&
                        probe.get("encrypted_key", "∅") == "encrypted_value"
                } catch (t: Throwable) {
                    false   // CorruptionException / multiple-DataStores race → not durable yet
                } finally {
                    runCatching { probe?.close() }
                }
                if (!durable) NSThread.sleepForTimeInterval(0.1)
            }
            assertTrue(
                durable,
                "1.x DataStore file never became readable after close() — write-durability race",
            )

            assertTrue(fileExists(legacyPath), "Setup: legacy file should exist after writing")
            assertFalse(fileExists(newPath), "Setup: new path should be empty before migration")

            // Default `directory = null` → auto-migration runs.
            val migrated = KSafe(fileName = name, testEngine = FakeEncryption())
            try {
                assertFalse(fileExists(legacyPath), "Legacy file should have moved")
                assertTrue(fileExists(newPath), "File should now live at NSApplicationSupportDirectory")

                assertEquals("plain_value", migrated.get("plain_key", "DEFAULT"))
                assertEquals("encrypted_value", migrated.get("encrypted_key", "DEFAULT"))
            } finally {
                migrated.close()
            }
        } finally {
            deleteFileIfExists(legacyPath)
            deleteFileIfExists(newPath)
        }
    }

    /**
     * Migration should NOT run when the consumer explicitly passes a `directory`,
     * even if a legacy file happens to exist in NSDocumentDirectory.
     */
    @Test
    fun explicitDirectory_skipsLegacyMigration() = runTest {
        val name = uniqueFileName("iosskipmig")
        val baseFileName = "eu_anifantakis_ksafe_datastore_$name"
        val legacyPath = "${documentsDirPath()}/$baseFileName.preferences_pb"
        val customDir = "${applicationSupportDirPath()}/ksafe_iostest_skipmig_$name"
        NSFileManager.defaultManager.createDirectoryAtPath(
            customDir,
            withIntermediateDirectories = true,
            attributes = null,
            error = null,
        )
        val customPath = "$customDir/$baseFileName.preferences_pb"

        deleteFileIfExists(legacyPath)
        deleteFileIfExists(customPath)

        try {
            writeBytesAt(legacyPath, "legacy-content-should-stay-put")
            assertTrue(fileExists(legacyPath))

            // Explicit `directory` → migration must not touch the legacy file.
            KSafe(fileName = name, directory = customDir, testEngine = FakeEncryption())

            assertTrue(
                fileExists(legacyPath),
                "Explicit `directory` should leave the legacy file alone",
            )
        } finally {
            deleteFileIfExists(legacyPath)
            NSFileManager.defaultManager.removeItemAtPath(customDir, error = null)
        }
    }

}
