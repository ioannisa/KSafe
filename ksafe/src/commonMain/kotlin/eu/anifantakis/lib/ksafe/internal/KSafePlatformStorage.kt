package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.flow.Flow

/**
 * Adapter over the platform persistent key-value store (Jetpack DataStore on
 * Android/iOS/JVM, Web Storage on wasmJs/js). All cache, encryption, metadata and
 * coalescing logic lives above this interface in [KSafeCore]. Keys arriving here are
 * already the final on-disk raw keys — the adapter adds or removes no prefixes.
 */
@PublishedApi
internal interface KSafePlatformStorage {

    /** One-shot bulk read of the entire store. */
    suspend fun snapshot(): Map<String, StoredValue>

    /** Stream of full-store snapshots, each reflecting the latest on-disk state. Re-collection must re-deliver the current snapshot: `getFlowRaw` resubscribes to recover from a transient decrypt failure. */
    fun snapshotFlow(): Flow<Map<String, StoredValue>>

    /**
     * Applies a batch of writes/deletes atomically when the backend supports it
     * (DataStore's single `edit {}` block); otherwise applies the ops in order.
     */
    suspend fun applyBatch(ops: List<StorageOp>)

    /** Removes every entry. */
    suspend fun clear()
}

/**
 * Typed stored value. Preserves DataStore's native primitive types on disk; encrypted
 * blobs and JSON-serialised user objects arrive as [Text].
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
 * Flattens a value for the string-only backends (the JSON file store, Web Storage): the type
 * is recovered on read from the stored text, so this must stay their single spelling of it.
 */
internal fun StoredValue.asString(): String = when (this) {
    is StoredValue.BoolVal -> value.toString()
    is StoredValue.IntVal -> value.toString()
    is StoredValue.LongVal -> value.toString()
    is StoredValue.FloatVal -> value.toString()
    is StoredValue.DoubleVal -> value.toString()
    is StoredValue.Text -> value
}

@PublishedApi
internal sealed interface StorageOp {
    val rawKey: String

    data class Put(override val rawKey: String, val value: StoredValue) : StorageOp
    data class Delete(override val rawKey: String) : StorageOp
}

/** Unwraps the native Kotlin value; the memory cache stores native types. */
@PublishedApi
internal fun StoredValue.toCacheValue(): Any = when (this) {
    is StoredValue.IntVal -> value
    is StoredValue.LongVal -> value
    is StoredValue.FloatVal -> value
    is StoredValue.DoubleVal -> value
    is StoredValue.BoolVal -> value
    is StoredValue.Text -> value
}

/** Wraps a primitive; complex values must already be JSON-encoded to [StoredValue.Text]. */
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
