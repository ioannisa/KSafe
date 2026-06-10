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
 * Software [JvmKeyVault] that stores AES keys Base64-encoded in a plain JSON
 * file — the fallback used (in place of [DataStoreKeyVault]) when KSafe runs on
 * the JSON-file storage backend because `sun.misc.Unsafe` is unavailable.
 *
 * [DataStoreKeyVault] persists keys through Jetpack DataStore, whose protobuf
 * requires `sun.misc.Unsafe`; on a `jlink`-trimmed runtime that omits
 * `jdk.unsupported` it crashes. This vault avoids DataStore/protobuf entirely.
 *
 * Security is identical to [DataStoreKeyVault]: none beyond OS file permissions
 * (the key sits next to the ciphertext). It's the no-OS-store software tier, so
 * `isOsBacked = false`. The file lives in the same `0700` directory as the data.
 * Writes are atomic (temp file + `ATOMIC_MOVE`).
 */
@OptIn(ExperimentalEncodingApi::class)
internal class FileKeyVault(
    private val file: File,
) : JvmKeyVault {

    override val name: String = "JSON file (software, plaintext — no OS protection)"
    override val isOsBacked: Boolean = false

    private val json = Json { encodeDefaults = true }
    private val ser = MapSerializer(String.serializer(), String.serializer())

    @Synchronized
    private fun read(): MutableMap<String, String> {
        // A missing file genuinely means "no keys yet" — empty is correct.
        if (!file.exists()) return mutableMapOf()
        // A file that EXISTS but can't be read or parsed must surface as an error,
        // not an empty vault: every key would look absent and the startup orphan
        // sweep would delete still-recoverable ciphertext.
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
        // Create the temp file owner-only (rw-------) ATOMICALLY where the
        // filesystem supports POSIX permissions, so the plaintext AES key is
        // never written into a momentarily group/world-readable file. On
        // non-POSIX filesystems (Windows) there is no perm-on-create; the parent
        // directory is already locked down (0700 / user ACL) — the same
        // protection the key file itself relies on. ATOMIC_MOVE preserves the
        // temp file's permissions onto the destination.
        val tmp = createOwnerOnlyTempFile(parent)
        try {
            // fsync BEFORE the atomic rename: a journaling filesystem can persist
            // the rename metadata before the temp file's data blocks, so a crash
            // right after the move could leave the destination zero-length. This
            // file holds the ONLY copy of the master AES key, and a blank file is
            // indistinguishable from "no keys yet" — the startup orphan sweep would
            // then delete every encrypted entry.
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
            // Non-POSIX filesystem (e.g. Windows): no atomic perm-on-create. The
            // parent directory's 0700 / ACL is the protection here.
            File.createTempFile(file.name, ".tmp", parent)
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
