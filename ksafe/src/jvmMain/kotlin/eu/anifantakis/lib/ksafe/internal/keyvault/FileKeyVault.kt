package eu.anifantakis.lib.ksafe.internal.keyvault

import eu.anifantakis.lib.ksafe.decodeBase64
import eu.anifantakis.lib.ksafe.encodeBase64
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions

/** Software [JvmKeyVault] holding Base64 AES keys in a plain JSON file, used when KSafe runs on
 *  the JSON-file backend. No protection beyond OS file permissions, so `isOsBacked = false`. */
internal class FileKeyVault(
    private val file: File,
    /** fsyncs the directory so a preceding atomic rename is durable; a no-op on Windows. */
    private val syncDir: (File) -> Unit = ::fsyncDirectory,
) : JvmKeyVault {

    override val name: String = "JSON file (software, plaintext — no OS protection)"
    override val isOsBacked: Boolean = false

    private val json = Json { encodeDefaults = true }
    private val ser = MapSerializer(String.serializer(), String.serializer())

    @Synchronized
    private fun read(): MutableMap<String, String> {
        if (!file.exists()) return mutableMapOf()
        // Fail closed: an existing-but-unreadable file must throw, not read as empty —
        // else every key looks absent and the orphan sweep deletes recoverable ciphertext.
        val text = try {
            file.readText()
        } catch (e: Throwable) {
            throw IllegalStateException("KSafe: key vault file unreadable: ${file.name}", e)
        }
        // A blank file is truncation, never a fresh store — write() always emits at least "{}"
        // and clearAll() deletes the file — so it fails closed too.
        if (text.isBlank()) {
            throw IllegalStateException("KSafe: key vault file is blank (truncated?): ${file.name}")
        }
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
        // Sweep crash-leftover temp files first: each holds the full plaintext key map.
        deleteStaleTempFiles(parent)
        // Owner-only so the plaintext key is never group/world-readable; ATOMIC_MOVE carries the perms.
        val tmp = createOwnerOnlyTempFile(parent)
        try {
            // fsync data BEFORE the rename: a journaling FS can persist the rename first, leaving
            // a zero-length destination that reads as "no keys yet" and gets swept.
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
            // fsync the parent dir too, or a crash loses the rename and the file reads as empty.
            val dir = file.absoluteFile.parentFile
            if (dir != null) syncDir(dir)
        } catch (e: Throwable) {
            runCatching { tmp.delete() }
            throw e
        }
    }

    /** Deletes `<file.name>*.tmp` orphans of a write that died before the move — each a full
     *  plaintext copy of the key map. Never deletes the key file itself. */
    private fun deleteStaleTempFiles(parent: File?) {
        val dir = parent ?: file.absoluteFile.parentFile ?: return
        runCatching {
            dir.listFiles()?.forEach { f ->
                if (f.name != file.name && f.name.startsWith(file.name) && f.name.endsWith(KEY_VAULT_TEMP_SUFFIX)) {
                    runCatching { f.delete() }
                }
            }
        }
    }

    private fun createOwnerOnlyTempFile(parent: File?): File {
        val dir = parent ?: file.absoluteFile.parentFile
        return try {
            Files.createTempFile(
                dir.toPath(),
                file.name,
                KEY_VAULT_TEMP_SUFFIX,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
            ).toFile()
        } catch (_: UnsupportedOperationException) {
            // Non-POSIX filesystem (Windows): no perms on create; the file inherits the parent directory's ACL.
            File.createTempFile(file.name, KEY_VAULT_TEMP_SUFFIX, parent)
        }
    }

    private companion object {
        // Best-effort: a directory cannot be opened as a channel on Windows.
        fun fsyncDirectory(dir: File) {
            runCatching {
                java.nio.channels.FileChannel.open(dir.toPath(), java.nio.file.StandardOpenOption.READ)
                    .use { it.force(true) }
            }
        }
    }

    @Synchronized
    override fun get(alias: String): ByteArray? = read()[alias]?.let { decodeBase64(it) }

    @Synchronized
    override fun put(alias: String, keyBytes: ByteArray) {
        val map = read()
        map[alias] = encodeBase64(keyBytes)
        write(map)
    }

    @Synchronized
    override fun delete(alias: String) {
        val map = read()
        if (map.remove(alias) != null) write(map)
    }

    /** Wipes every key: deleting the file and its temp copies is the only way to reclaim the
     *  orphans per-alias deletes miss. Runs on the write consumer, so it can't race a write. */
    @Synchronized
    override fun clearAll() {
        deleteStaleTempFiles(file.parentFile)
        runCatching { file.delete() }
    }
}

/** Suffix of [FileKeyVault]'s staging files, each a full plaintext key map: the residue sweeps
 *  that live in other files must match the same name. */
internal const val KEY_VAULT_TEMP_SUFFIX: String = ".tmp"
