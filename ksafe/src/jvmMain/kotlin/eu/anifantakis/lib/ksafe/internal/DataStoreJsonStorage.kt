package eu.anifantakis.lib.ksafe.internal

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.Serializer
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File
import java.io.InputStream
import java.io.OutputStream

/**
 * [KSafePlatformStorage] for the JVM fallback that avoids `sun.misc.Unsafe`.
 *
 * DataStore Preferences' protobuf hard-requires `sun.misc.Unsafe`, which a `jlink`-trimmed
 * runtime (omitting `jdk.unsupported`) crashes on. This keeps DataStore's file machinery
 * (atomic writes, corruption handling, fsync) but swaps in a plain JSON serializer.
 *
 * Uses `datastore-core`'s `java.io` [Serializer] path, not okio: okio 3.x's multi-release
 * jar fails bytecode verification (`VerifyError: Bad return type`) on the jlink-trimmed runtime.
 */
@PublishedApi
internal class DataStoreJsonStorage(
    file: File,
    scope: CoroutineScope,
) : KSafePlatformStorage {

    private val dataStore: DataStore<Map<String, String>> = DataStoreFactory.create(
        serializer = JsonMapSerializer,
        corruptionHandler = ReplaceFileCorruptionHandler {
            quarantineCorruptStoreFile(file)
            emptyMap()
        },
        scope = scope,
        produceFile = { file },
    )

    private val commits = DataStoreCommitRelay(dataStore) { m ->
        m.mapValues { StoredValue.Text(it.value) }
    }

    override suspend fun snapshot(): Map<String, StoredValue> = commits.snapshot()

    override fun snapshotFlow(): Flow<Map<String, StoredValue>> = commits.snapshotFlow()

    override suspend fun applyBatch(ops: List<StorageOp>) {
        if (ops.isEmpty()) return
        commits.publish(
            dataStore.updateData { current ->
                val out = current.toMutableMap()
                for (op in ops) when (op) {
                    is StorageOp.Put -> out[op.rawKey] = op.value.asString()
                    is StorageOp.Delete -> out.remove(op.rawKey)
                }
                out
            }
        )
    }

    override suspend fun clear() {
        commits.publish(dataStore.updateData { emptyMap() })
    }

    /** JSON `Map<String,String>` serializer over `java.io` streams — no protobuf, no okio. */
    internal object JsonMapSerializer : Serializer<Map<String, String>> {
        private val json = Json { encodeDefaults = true }
        private val mapSer = MapSerializer(String.serializer(), String.serializer())

        override val defaultValue: Map<String, String> = emptyMap()

        override suspend fun readFrom(input: InputStream): Map<String, String> {
            // A mid-read IOException must propagate, not return emptyMap: datastore-core
            // caches readFrom's result as current state, so emptying here lets the next
            // write wipe every entry over a transient hiccup. (Missing file never reaches
            // here — datastore-core yields defaultValue for FileNotFoundException.)
            val text = input.readBytes().decodeToString()
            return try {
                if (text.isBlank()) emptyMap() else json.decodeFromString(mapSer, text)
            } catch (e: SerializationException) {
                // Non-blank but unparseable = real corruption; route to corruptionHandler.
                throw CorruptionException("KSafe JSON store is corrupt: unparseable content", e)
            }
        }

        override suspend fun writeTo(t: Map<String, String>, output: OutputStream) {
            output.write(json.encodeToString(mapSer, t).encodeToByteArray())
        }
    }
}
