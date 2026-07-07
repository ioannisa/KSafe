package eu.anifantakis.lib.ksafe.internal.keyvault

import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Software [JvmKeyVault] storing AES keys Base64-encoded in a plain JSON file —
 * the fallback used when KSafe runs on the JSON-file backend (no DataStore,
 * whose protobuf needs `sun.misc.Unsafe`, absent on a jlink-trimmed runtime that
 * omits `jdk.unsupported`).
 *
 * Security: none beyond OS file permissions (the key sits next to the
 * ciphertext), so `isOsBacked = false`. Writes are atomic (temp file +
 * `ATOMIC_MOVE`) in the same `0700` directory as the data.
 */
@OptIn(ExperimentalEncodingApi::class)
internal class FileKeyVault(
    private val file: File,
    /**
     * fsyncs the given directory so a preceding atomic rename into it is durable.
     * Injectable for tests; best-effort (a no-op where a directory can't be opened
     * as a channel, e.g. Windows).
     */
    private val syncDir: (File) -> Unit = ::fsyncDirectory,
) : JvmKeyVault {

    override val name: String = "JSON file (software, plaintext — no OS protection)"
    override val isOsBacked: Boolean = false

    private val json = Json { encodeDefaults = true }
    private val ser = MapSerializer(String.serializer(), String.serializer())

    @Synchronized
    private fun read(): MutableMap<String, String> {
        // A missing file means "no keys yet" — empty is correct.
        if (!file.exists()) return mutableMapOf()
        // But a file that EXISTS yet can't be read/parsed must throw, not read as empty:
        // every key would look absent and the orphan sweep would delete recoverable ciphertext.
        val text = try {
            file.readText()
        } catch (e: Throwable) {
            throw IllegalStateException("KSafe: key vault file unreadable: ${file.name}", e)
        }
        if (text.isBlank()) return mutableMapOf()
        return try {
            json.decodeFromString(ser, text).toMutableMap()
        } catch (e: Throwable) {
            throw IllegalStateException("KSafe: key vault file corrupt: ${file.name}", e)
        }
    }

    @Synchronized
    private fun write(map: Map<String, String>) {
        val parent = file.parentFile
        if (parent != null && !parent.exists()) parent.mkdirs()
        // Temp file created owner-only (rw-------) so the plaintext AES key is never briefly
        // group/world-readable; ATOMIC_MOVE carries those perms onto the destination.
        // Non-POSIX filesystems (Windows) rely on the 0700 parent dir instead.
        val tmp = createOwnerOnlyTempFile(parent)
        try {
            // fsync the data BEFORE the rename: a journaling FS may persist the rename ahead
            // of the temp file's blocks, leaving a zero-length destination on a crash. This
            // holds the only copy of the master key, and a blank file reads as "no keys yet"
            // — the orphan sweep would then delete every entry.
            java.io.FileOutputStream(tmp).use { out ->
                out.write(json.encodeToString(ser, map).encodeToByteArray())
                out.flush()
                out.fd.sync()
            }
            Files.move(
                tmp.toPath(),
                file.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            // fsync the PARENT DIRECTORY too, so the rename (a directory-entry change) is
            // durable. The data fsync above persists only the temp file's blocks; without
            // this, a crash after the move can lose the rename and leave the key file missing
            // — which reads as "no keys yet" and the orphan sweep deletes every entry.
            val dir = file.absoluteFile.parentFile
            if (dir != null) syncDir(dir)
        } catch (e: Throwable) {
            runCatching { tmp.delete() }
            throw e
        }
    }

    private fun createOwnerOnlyTempFile(parent: File?): File {
        val dir = parent ?: file.absoluteFile.parentFile
        return try {
            Files.createTempFile(
                dir.toPath(),
                file.name,
                ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
            ).toFile()
        } catch (_: UnsupportedOperationException) {
            // Non-POSIX filesystem (Windows): no perm-on-create; the 0700 parent dir protects it.
            File.createTempFile(file.name, ".tmp", parent)
        }
    }

    private companion object {
        /**
         * Best-effort fsync of [dir] so a preceding atomic rename into it survives a crash.
         * Opening a directory as a channel is POSIX-only; swallowed on Windows, where the
         * data fsync + atomic move are the durability guarantee.
         */
        fun fsyncDirectory(dir: File) {
            runCatching {
                java.nio.channels.FileChannel.open(dir.toPath(), java.nio.file.StandardOpenOption.READ)
                    .use { it.force(true) }
            }
        }
    }

    @Synchronized
    override fun get(alias: String): ByteArray? = read()[alias]?.let { Base64.decode(it) }

    @Synchronized
    override fun put(alias: String, keyBytes: ByteArray) {
        val map = read()
        map[alias] = Base64.encode(keyBytes)
        write(map)
    }

    @Synchronized
    override fun delete(alias: String) {
        val map = read()
        if (map.remove(alias) != null) write(map)
    }
}
