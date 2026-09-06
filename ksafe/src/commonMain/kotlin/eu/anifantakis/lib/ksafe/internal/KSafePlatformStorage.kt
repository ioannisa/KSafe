package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.flow.Flow

/**
 * Adapter over the platform key-value store (DataStore, Web Storage). Keys arriving here are
 * already the final on-disk raw keys; cache, encryption and metadata live above it in [KSafeCore].
 */
@PublishedApi
internal interface KSafePlatformStorage {

    suspend fun snapshot(): Map<String, StoredValue>

    /** Re-collection must re-deliver the current snapshot; `getFlowRaw` resubscribes to retry. */
    fun snapshotFlow(): Flow<Map<String, StoredValue>>

    /** Atomic when the backend supports it (one DataStore `edit {}`), else applied in order. */
    suspend fun applyBatch(ops: List<StorageOp>)

    suspend fun clear()
}

/** Preserves the store's native primitive types; encrypted blobs and JSON arrive as [Text]. */
@PublishedApi
internal sealed interface StoredValue {
    data class IntVal(val value: Int) : StoredValue
    data class LongVal(val value: Long) : StoredValue
    data class FloatVal(val value: Float) : StoredValue
    data class DoubleVal(val value: Double) : StoredValue
    data class BoolVal(val value: Boolean) : StoredValue
    data class Text(val value: String) : StoredValue
}

/** The single spelling for the string-only backends: the type is recovered from this text on read. */
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
