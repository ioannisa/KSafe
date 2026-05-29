package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.Serializer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * [KSafePlatformStorage] for the JVM **no-`sun.misc.Unsafe` fallback** — backed by
 * Jetpack **`datastore-core`** with a custom JSON [Serializer] instead of the
 * DataStore *Preferences* serializer.
 *
 * The normal JVM backend ([DataStoreStorage]) uses DataStore Preferences, whose
 * embedded protobuf (`androidx.datastore.preferences.protobuf.*`) hard-requires
 * `sun.misc.Unsafe`; on a `jlink`-trimmed runtime that omits `jdk.unsupported`
 * it crashes the app. This adapter keeps DataStore's proven file machinery —
 * atomic writes, the single-process coordinator, corruption handling, fsync —
 * but swaps the serializer for a plain JSON one (kotlinx-serialization, already
 * on the classpath). It never references the Preferences protobuf, so those
 * classes are never loaded and `Unsafe` is never touched.
 *
 * It deliberately uses `datastore-core`'s **`java.io`** [Serializer] +
 * `produceFile` path (the same `FileStorage` the Preferences backend rides on),
 * **not** the okio variant: okio 3.x ships a multi-release jar whose internal
 * `JvmSystemFileSystem` fails bytecode verification (`VerifyError: Bad return
 * type`) on Compose's jlink-trimmed runtime. The `java.io` path has no such
 * issue and is already exercised on this runtime by the normal backend.
 *
 * As with [LocalStorageStorage] on web, every [StoredValue] flattens to its
 * string form on disk; [KSafeCore] re-types primitives via the request's
 * serializer on read. Encryption happens above this layer — bytes here are
 * already ciphertext (or plaintext for `KSafeWriteMode.Plain`).
 */
@PublishedApi
internal class DataStoreJsonStorage(
    file: File,
    scope: CoroutineScope,
) : KSafePlatformStorage {

    private val dataStore: DataStore<Map<String, String>> = DataStoreFactory.create(
        serializer = JsonMapSerializer,
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

    /** JSON `Map<String,String>` serializer over `java.io` streams — no protobuf, no okio. */
    private object JsonMapSerializer : Serializer<Map<String, String>> {
        private val json = Json { encodeDefaults = true }
        private val mapSer = MapSerializer(String.serializer(), String.serializer())

        override val defaultValue: Map<String, String> = emptyMap()

        override suspend fun readFrom(input: InputStream): Map<String, String> {
            val text = try {
                input.readBytes().decodeToString()
            } catch (_: IOException) {
                // Unreadable file → behave like a fresh store.
                return emptyMap()
            }
            return try {
                if (text.isBlank()) emptyMap() else json.decodeFromString(mapSer, text)
            } catch (_: SerializationException) {
                // Corrupt/partial content → behave like a fresh store rather than
                // surfacing a CorruptionException as a read-path crash.
                emptyMap()
            }
        }

        override suspend fun writeTo(t: Map<String, String>, output: OutputStream) {
            output.write(json.encodeToString(mapSer, t).encodeToByteArray())
        }
    }
}
