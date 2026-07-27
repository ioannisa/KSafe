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
internal class FileKeyVault(
    private val file: File,
    /**
     * fsyncs the directory so a preceding atomic rename is durable. Injectable for
     * tests; best-effort no-op where a directory can't be opened as a channel (Windows).
     */
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
        // An existing-but-blank file is truncation, never a fresh store — write() always emits
        // at least "{}" and clearAll() deletes the file — so it must fail closed like the
        // unreadable/corrupt branches, not read as "no keys yet".
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
        // Owner-only (rw-------) so the plaintext AES key is never group/world-readable;
        // ATOMIC_MOVE carries the perms to the destination. Windows relies on the 0700 dir.
        val tmp = createOwnerOnlyTempFile(parent)
        try {
            // fsync data BEFORE the rename: a journaling FS can persist the rename ahead of the
            // temp file's blocks, leaving a zero-length destination that reads as "no keys yet"
            // — the orphan sweep then deletes every entry.
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
            // fsync the parent dir too, so the rename itself is durable — else a crash can lose
            // it and leave the key file missing, which reads as "no keys yet" and gets swept.
            val dir = file.absoluteFile.parentFile
            if (dir != null) syncDir(dir)
        } catch (e: Throwable) {
            runCatching { tmp.delete() }
            throw e
        }
    }

    /**
     * Deletes `<file.name>*.tmp` orphans from a write that died before the atomic move — each
     * is a full plaintext copy of the key map. Best-effort; never deletes the key file itself.
     */
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
            // Non-POSIX filesystem (Windows): no perm-on-create; the 0700 parent dir protects it.
            File.createTempFile(file.name, KEY_VAULT_TEMP_SUFFIX, parent)
        }
    }

    private companion object {
        /**
         * Best-effort fsync of [dir] so a preceding atomic rename survives a crash. Opening a
         * directory as a channel is POSIX-only; swallowed on Windows.
         */
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

    /**
     * Wipes EVERY key (this file is a per-store plaintext key map, so removing it in whole is
     * safe and is the only way to reclaim keys the per-alias deletes miss — orphans and
     * `getOrCreateSecret` slots). Deleting the physical file + its crash-leftover temp copies
     * leaves no plaintext key material behind. Called on the write consumer, so it never races
     * a concurrent write; a subsequent write re-creates the file with the fresh key.
     */
    @Synchronized
    override fun clearAll() {
        deleteStaleTempFiles(file.parentFile)
        runCatching { file.delete() }
    }
}

/**
 * Suffix of [FileKeyVault]'s atomic-write staging files. Each is a full plaintext copy of the AES
 * key map, so the store's own crash-leftover sweep and `clearAll`'s residue sweep — in a different
 * file — must recognise exactly the same name. (`JvmFallbackMigration`'s pending-state temp shares
 * the spelling by coincidence, not by contract, and deliberately does not use this.)
 */
internal const val KEY_VAULT_TEMP_SUFFIX: String = ".tmp"
