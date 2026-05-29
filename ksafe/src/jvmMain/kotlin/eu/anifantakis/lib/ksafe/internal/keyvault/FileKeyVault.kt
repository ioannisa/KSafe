package eu.anifantakis.lib.ksafe.internal.keyvault

import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
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
        if (!file.exists()) return mutableMapOf()
        return try {
            val text = file.readText()
            if (text.isBlank()) mutableMapOf() else json.decodeFromString(ser, text).toMutableMap()
        } catch (_: Throwable) {
            mutableMapOf()
        }
    }

    @Synchronized
    private fun write(map: Map<String, String>) {
        val parent = file.parentFile
        if (parent != null && !parent.exists()) parent.mkdirs()
        val tmp = File.createTempFile(file.name, ".tmp", parent)
        try {
            tmp.writeText(json.encodeToString(ser, map))
            runCatching { tmp.setReadable(true, true); tmp.setWritable(true, true) }
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
