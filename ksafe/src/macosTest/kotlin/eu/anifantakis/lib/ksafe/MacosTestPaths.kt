package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import kotlin.concurrent.AtomicInt
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Helpers for macOS unit tests.
 *
 * macOS tests must NEVER write to `NSApplicationSupportDirectory`
 * (`~/Library/Application Support/`) — on a developer's machine that
 * directory is real, persistent and shared with every other app, so test
 * residue would accumulate. iOS Simulator tests get away with using it
 * because each simulator boots into its own per-instance sandbox.
 *
 * Everything here routes through [NSTemporaryDirectory], which on macOS
 * resolves to a per-user, per-session location under `/var/folders/...`
 * that the OS cleans up periodically and is gitignore-safe.
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalUuidApi::class)
internal object MacosTestPaths {

    private val counter = AtomicInt(0)

    /**
     * Allocate (and create on disk) a unique temporary directory for a single
     * test. Returns the absolute path. Safe to call repeatedly — every
     * invocation gets its own directory.
     */
    fun uniqueTempDir(prefix: String = "ksafe-macostest"): String {
        val salt = counter.incrementAndGet().toString(36)
        val uuid = Uuid.random().toString().lowercase().filter { it in 'a'..'z' || it in '0'..'9' }.take(8)
        val dir = "${NSTemporaryDirectory()}$prefix-$salt-$uuid"
        NSFileManager.defaultManager.createDirectoryAtPath(
            dir,
            withIntermediateDirectories = true,
            attributes = null,
            error = null,
        )
        return dir
    }

    /**
     * Lowercase, alphanumeric, KSafe-regex-safe filename. The library requires
     * names match `[a-z][a-z0-9_]*`, so we strip everything else.
     */
    fun uniqueFileName(prefix: String = "macos"): String {
        val salt = counter.incrementAndGet().toString(36).filter { it in 'a'..'z' || it in '0'..'9' }.ifEmpty { "x" }
        val uuid = Uuid.random().toString().lowercase().filter { it in 'a'..'z' }.take(8).ifEmpty { "ksafe" }
        return "${prefix}_${salt}_$uuid"
    }

    /** Best-effort recursive delete. Used for teardown. */
    fun deleteRecursively(path: String) {
        NSFileManager.defaultManager.removeItemAtPath(path, error = null)
    }

    fun fileExists(path: String): Boolean =
        NSFileManager.defaultManager.fileExistsAtPath(path)
}
