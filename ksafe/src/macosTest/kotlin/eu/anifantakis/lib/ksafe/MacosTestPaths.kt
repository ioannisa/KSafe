package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import kotlin.concurrent.AtomicInt
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Path helpers for macOS unit tests. Everything routes through [NSTemporaryDirectory],
 * never `NSApplicationSupportDirectory` (`~/Library/Application Support/`), which on a real
 * Mac is persistent and shared across apps so test residue would accumulate.
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalUuidApi::class)
internal object MacosTestPaths {

    private val counter = AtomicInt(0)

    /** Creates and returns a unique temp directory; safe to call repeatedly. */
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

    /** Unique filename matching KSafe's required `[a-z][a-z0-9_]*` pattern. */
    fun uniqueFileName(prefix: String = "macos"): String {
        val salt = counter.incrementAndGet().toString(36).filter { it in 'a'..'z' || it in '0'..'9' }.ifEmpty { "x" }
        val uuid = Uuid.random().toString().lowercase().filter { it in 'a'..'z' }.take(8).ifEmpty { "ksafe" }
        return "${prefix}_${salt}_$uuid"
    }

    /** Best-effort recursive delete. */
    fun deleteRecursively(path: String) {
        NSFileManager.defaultManager.removeItemAtPath(path, error = null)
    }

    fun fileExists(path: String): Boolean =
        NSFileManager.defaultManager.fileExistsAtPath(path)
}
