package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.Serializer
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File
import java.io.InputStream
import java.io.OutputStream

/**
 * [KSafePlatformStorage] for the JVM no-`sun.misc.Unsafe` fallback — `datastore-core`
 * with a custom JSON [Serializer] instead of the DataStore Preferences serializer.
 *
 * DataStore Preferences' embedded protobuf hard-requires `sun.misc.Unsafe`, which a
 * `jlink`-trimmed runtime (omitting `jdk.unsupported`) crashes on. This keeps DataStore's
 * file machinery (atomic writes, single-process coordinator, corruption handling, fsync)
 * but swaps in a plain JSON serializer, so the Preferences protobuf is never loaded.
 *
 * Uses `datastore-core`'s `java.io` [Serializer] + `produceFile` path, not the okio
 * variant: okio 3.x's multi-release jar fails bytecode verification (`VerifyError: Bad
 * return type`) on Compose's jlink-trimmed runtime.
 *
 * Every [StoredValue] flattens to its string form on disk; [KSafeCore] re-types primitives
 * via the request's serializer on read. Encryption happens above this layer.
 */
@PublishedApi
internal class DataStoreJsonStorage(
    file: File,
    scope: CoroutineScope,
) : KSafePlatformStorage {

    private val dataStore: DataStore<Map<String, String>> = DataStoreFactory.create(
        serializer = JsonMapSerializer,
        // On genuine corruption the serializer throws CorruptionException; copy the
        // unparseable bytes aside for recovery before continuing from an empty store.
        corruptionHandler = ReplaceFileCorruptionHandler {
            runCatching {
                file.copyTo(
                    File(file.parentFile, "${file.name}.corrupt-${System.currentTimeMillis()}"),
                    overwrite = false,
                )
            }
            emptyMap()
        },
        scope = scope,
        produceFile = { file },
    )

    override suspend fun snapshot(): Map<String, StoredValue> =
        dataStore.data.first().mapValues { StoredValue.Text(it.value) }

    override fun snapshotFlow(): Flow<Map<String, StoredValue>> =
        dataStore.data.map { m -> m.mapValues { StoredValue.Text(it.value) } }

    override suspend fun applyBatch(ops: List<StorageOp>) {
        if (ops.isEmpty()) return
        dataStore.updateData { current ->
            val out = current.toMutableMap()
            for (op in ops) when (op) {
                is StorageOp.Put -> out[op.rawKey] = op.value.asString()
                is StorageOp.Delete -> out.remove(op.rawKey)
            }
            out
        }
    }

    override suspend fun clear() {
        dataStore.updateData { emptyMap() }
    }

    private fun StoredValue.asString(): String = when (this) {
        is StoredValue.BoolVal -> value.toString()
        is StoredValue.IntVal -> value.toString()
        is StoredValue.LongVal -> value.toString()
        is StoredValue.FloatVal -> value.toString()
        is StoredValue.DoubleVal -> value.toString()
        is StoredValue.Text -> value
    }

    /** JSON `Map<String,String>` serializer over `java.io` streams — no protobuf, no okio. */
    internal object JsonMapSerializer : Serializer<Map<String, String>> {
        private val json = Json { encodeDefaults = true }
        private val mapSer = MapSerializer(String.serializer(), String.serializer())

        override val defaultValue: Map<String, String> = emptyMap()

        override suspend fun readFrom(input: InputStream): Map<String, String> {
            // A mid-read IOException on an existing file must propagate, not become an
            // empty store: datastore-core caches readFrom's return as current state, so
            // emptyMap() here lets the next write atomically wipe every entry over a
            // transient hiccup. (A missing file never reaches here — datastore-core
            // yields defaultValue for FileNotFoundException.)
            val text = input.readBytes().decodeToString()
            return try {
                if (text.isBlank()) emptyMap() else json.decodeFromString(mapSer, text)
            } catch (e: SerializationException) {
                // Non-blank but unparseable = real corruption. Route to the
                // corruptionHandler rather than treating recoverable bytes as empty.
                throw CorruptionException("KSafe JSON store is corrupt: unparseable content", e)
            }
        }

        override suspend fun writeTo(t: Map<String, String>, output: OutputStream) {
            output.write(json.encodeToString(mapSer, t).encodeToByteArray())
        }
    }
}
