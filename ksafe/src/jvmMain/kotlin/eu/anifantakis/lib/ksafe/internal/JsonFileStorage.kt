package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * [KSafePlatformStorage] backed by a plain JSON file — the JVM **fallback** used
 * when `sun.misc.Unsafe` is unavailable (a Compose Desktop release distributable
 * whose `jlink` runtime omits `jdk.unsupported`).
 *
 * KSafe's normal JVM backend is Jetpack DataStore Preferences, but DataStore's
 * embedded protobuf hard-requires `sun.misc.Unsafe` to (de)serialise its file —
 * so on a trimmed runtime it crashes the app on first read/write, which KSafe
 * cannot catch (the failure is inside DataStore on a background coroutine). This
 * adapter avoids protobuf entirely: it serialises the store to a JSON object via
 * `kotlinx-serialization` (already on the classpath) and never touches `Unsafe`.
 * (Verified: of every jar KSafe ships, only `datastore-preferences-external-protobuf`
 * references `sun/misc/Unsafe`.)
 *
 * Like [LocalStorageStorage] on web, every [StoredValue] flattens to its string
 * form on disk; [KSafeCore] reconstitutes the original type on read using the
 * request's `KSerializer` (the same slow path the web target relies on). All
 * encryption still happens above this layer — the bytes stored here are already
 * AES-GCM ciphertext (or plaintext for `KSafeWriteMode.Plain`).
 *
 * Durability: writes are atomic (write to a sibling temp file, then
 * `ATOMIC_MOVE` over the target), so a crash mid-write can't corrupt the store.
 * The file lives in the same `0700` directory the DataStore file would.
 */
@PublishedApi
internal class JsonFileStorage(
    private val file: File,
) : KSafePlatformStorage {

    private val json = Json { encodeDefaults = true }
    private val mapSerializer = MapSerializer(String.serializer(), String.serializer())

    /** Serialises writes; reads go through the lock-free [changes] StateFlow. */
    private val writeMutex = Mutex()

    private val changes = MutableStateFlow(readFromDisk())

    override suspend fun snapshot(): Map<String, StoredValue> = changes.value

    override fun snapshotFlow(): Flow<Map<String, StoredValue>> = changes.asStateFlow()

    override suspend fun applyBatch(ops: List<StorageOp>) {
        if (ops.isEmpty()) return
        writeMutex.withLock {
            // Work on the string form (what we persist); the StateFlow exposes
            // StoredValue.Text so the rest of KSafe sees a uniform shape.
            val current = HashMap<String, String>()
            changes.value.forEach { (k, v) -> current[k] = (v as StoredValue.Text).value }
            for (op in ops) when (op) {
                is StorageOp.Put -> current[op.rawKey] = op.value.asString()
                is StorageOp.Delete -> current.remove(op.rawKey)
            }
            writeToDisk(current)
            changes.value = current.mapValues { StoredValue.Text(it.value) }
        }
    }

    override suspend fun clear() {
        writeMutex.withLock {
            runCatching { if (file.exists()) file.delete() }
            changes.value = emptyMap()
        }
    }

    // ---- disk I/O ----

    private fun readFromDisk(): Map<String, StoredValue> {
        if (!file.exists()) return emptyMap()
        return try {
            val text = file.readText()
            if (text.isBlank()) return emptyMap()
            json.decodeFromString(mapSerializer, text)
                .mapValues { StoredValue.Text(it.value) }
        } catch (_: Throwable) {
            // Corrupt/partial file: behave like a fresh store rather than crash.
            // (The atomic-move write below makes partial files unlikely.)
            emptyMap()
        }
    }

    private fun writeToDisk(map: Map<String, String>) {
        val parent = file.parentFile
        if (parent != null && !parent.exists()) parent.mkdirs()
        val tmp = File.createTempFile(file.name, ".tmp", parent)
        try {
            tmp.writeText(json.encodeToString(mapSerializer, map))
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

    /**
     * Every [StoredValue] collapses to its string form on disk; [KSafeCore]
     * re-types primitives through the request's serializer on read (same
     * contract as [LocalStorageStorage]).
     */
    private fun StoredValue.asString(): String = when (this) {
        is StoredValue.BoolVal -> value.toString()
        is StoredValue.IntVal -> value.toString()
        is StoredValue.LongVal -> value.toString()
        is StoredValue.FloatVal -> value.toString()
        is StoredValue.DoubleVal -> value.toString()
        is StoredValue.Text -> value
    }
}
