package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.flow.Flow

/**
 * Abstraction over the platform-specific persistent key-value store used by KSafe.
 *
 * Implementations wrap the underlying backend (Jetpack DataStore on Android/iOS/JVM,
 * Web Storage on wasmJs/js) and expose a narrow byte/primitive-oriented API. All
 * hot-cache, encryption, metadata and coalescing logic lives above this interface
 * in [KSafeCore] — the adapter is deliberately "dumb".
 *
 * Keys passed to this interface are already the final on-disk raw keys (e.g.
 * `__ksafe_value_foo`, `__ksafe_meta_foo__`) — the adapter does not add or remove
 * prefixes.
 */
@PublishedApi
internal interface KSafePlatformStorage {

    /**
     * One-shot bulk read of the entire store. Used for cold-start cache preload and
     * for orphan-ciphertext cleanup where we need to inspect every entry.
     */
    suspend fun snapshot(): Map<String, StoredValue>

    /**
     * Continuous stream of full-store snapshots. Each emission reflects the latest
     * on-disk state. Used to drive the hot cache and single-key [Flow] APIs.
     */
    fun snapshotFlow(): Flow<Map<String, StoredValue>>

    /**
     * Applies a batch of writes/deletes atomically when the backend supports it
     * (DataStore does — a single `edit {}` block). Implementations that lack true
     * atomicity must apply the ops in order.
     */
    suspend fun applyBatch(ops: List<StorageOp>)

    /**
     * Removes every entry. Used by `clearAll()`.
     */
    suspend fun clear()
}

/**
 * Typed value stored in the platform backend.
 *
 * Preserves DataStore's native primitive types on disk so numeric and boolean
 * entries survive round-tripping without going through JSON. Binary payloads
 * (encrypted blobs) and JSON-serialised user objects are represented as
 * [Text] — they are already strings by the time they reach this layer.
 */
@PublishedApi
internal sealed interface StoredValue {
    data class IntVal(val value: Int) : StoredValue
    data class LongVal(val value: Long) : StoredValue
    data class FloatVal(val value: Float) : StoredValue
    data class DoubleVal(val value: Double) : StoredValue
    data class BoolVal(val value: Boolean) : StoredValue
    data class Text(val value: String) : StoredValue
}

/**
 * A single operation inside a batch passed to [KSafePlatformStorage.applyBatch].
 */
@PublishedApi
internal sealed interface StorageOp {
    val rawKey: String

    data class Put(override val rawKey: String, val value: StoredValue) : StorageOp
    data class Delete(override val rawKey: String) : StorageOp
}

/**
 * Helpers to extract the underlying Kotlin value from a [StoredValue].
 * Used by [KSafeCore] when populating the memory cache — the cache stores native
 * types so existing `convertStoredValueRaw` logic continues to work unchanged.
 */
@PublishedApi
internal fun StoredValue.toCacheValue(): Any = when (this) {
    is StoredValue.IntVal -> value
    is StoredValue.LongVal -> value
    is StoredValue.FloatVal -> value
    is StoredValue.DoubleVal -> value
    is StoredValue.BoolVal -> value
    is StoredValue.Text -> value
}

/**
 * Wraps a primitive value in the appropriate [StoredValue] variant. Complex /
 * `@Serializable` values must be JSON-encoded to a string by the caller first and
 * passed as [StoredValue.Text].
 */
@PublishedApi
internal fun primitiveToStoredValue(value: Any): StoredValue = when (value) {
    is Boolean -> StoredValue.BoolVal(value)
    is Int -> StoredValue.IntVal(value)
    is Long -> StoredValue.LongVal(value)
    is Float -> StoredValue.FloatVal(value)
    is Double -> StoredValue.DoubleVal(value)
    is String -> StoredValue.Text(value)
    else -> error("primitiveToStoredValue: unsupported type ${value::class}")
}
