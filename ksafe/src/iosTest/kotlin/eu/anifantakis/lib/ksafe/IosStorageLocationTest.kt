package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.test.runTest
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSData
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSFileSize
import platform.Foundation.NSNumber
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
        private fun fileSize(path: String): Long {
            val attrs = NSFileManager.defaultManager.attributesOfItemAtPath(path, error = null)
            return (attrs?.get(NSFileSize) as? NSNumber)?.longLongValue ?: -1L
        }

        /**
         * Deterministically wait until [path] is a fully-written, stable file.
         *
         * `KSafe.close()` only cancels the storage scope — it does NOT flush
         * DataStore — and the suspend `put`'s durability is timing-sensitive
         * on the loaded CI iOS simulator. Reopening / migrating a
         * still-being-written `.preferences_pb` throws DataStore
         * `CorruptionException` (the pre-existing flake). This polls the real
         * on-disk size (a condition, NOT a fixed sleep) until it is non-zero
         * and unchanged across consecutive samples. Uses `NSThread` real sleep
         * because `runTest`'s virtual clock would skip a kotlinx `delay`.
         */
        @OptIn(ExperimentalForeignApi::class)
        fun awaitFileSettled(path: String) {
            var last = -1L
            var stable = 0
            repeat(200) {                       // ~10s ceiling (200 × 50ms)
                val sz = fileSize(path)
                if (sz > 0L && sz == last) {
                    if (++stable >= 3) return   // 3 consecutive equal, non-zero
                } else {
                    stable = 0
                }
                last = sz
                NSThread.sleepForTimeInterval(0.05)
            }
        }

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
        // Create the parent dir
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
            // Simulate a 1.x install: file present at the legacy NSDocumentDirectory
            // path, nothing at the new location yet.
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
     * 1.x → 2.0 auto-migration regression: writes encrypted data to a file
     * pinned at the legacy `NSDocumentDirectory` path (using FakeEncryption +
     * an explicit `directory` override to mimic the 1.x layout), then opens a
     * default-`directory = null` KSafe with the same `fileName`. The factory
     * should move the legacy file to `NSApplicationSupportDirectory` and the
     * data should still be readable.
     *
     * Mirrors the demo app's `customJsonKSafe` instance scenario:
     *     `KSafe(fileName = "appledata_customjson", config = KSafeConfig(json = ...))`
     * upgraded from 1.8.1 → 2.0.0.
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
            // Phase 1 — simulate "1.x install" by writing a real DataStore
            // Preferences file at NSDocumentDirectory through KSafe itself.
            // FakeEncryption is deterministic across instances (the alias is
            // the only input), so the second-instance read can decrypt what
            // the first instance wrote.
            val v1Like = KSafe(
                fileName = name,
                directory = documentsDirPath(),
                testEngine = FakeEncryption(),
            )
            v1Like.put("plain_key", "plain_value")
            v1Like.put("encrypted_key", "encrypted_value", KSafeWriteMode.Encrypted())
            v1Like.close()

            // Barrier: the simulated "1.x install" must be durably on disk
            // before the "next launch" migration reopens it. close() doesn't
            // flush DataStore; reopening a half-written file throws
            // CorruptionException (the pre-existing CI flake). Wait on the
            // real file size settling rather than racing it.
            awaitFileSettled(legacyPath)

            assertTrue(fileExists(legacyPath), "Setup: legacy file should exist after writing")
            assertFalse(fileExists(newPath), "Setup: new path should be empty before migration")

            // Phase 2 — default `directory = null` should auto-migrate the
            // file from NSDocumentDirectory to NSApplicationSupportDirectory.
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
