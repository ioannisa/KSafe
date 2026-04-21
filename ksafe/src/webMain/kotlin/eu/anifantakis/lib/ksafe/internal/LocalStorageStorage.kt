package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.yield

/**
 * [KSafePlatformStorage] backed by the browser's `localStorage`.
 *
 * localStorage is synchronous and stores only string values, so every
 * [StoredValue] flattens to its `.toString()` representation on write.
 * [KSafeCore.resolveFromCache] reconstitutes the original type using the
 * request's [KSerializer] — see `convertStoredValue`'s slow path.
 *
 * All keys this adapter touches on disk are prefixed with [storagePrefix] so
 * multiple `KSafe` instances with different `fileName`s share the same
 * localStorage namespace without colliding.
 *
 * Change observation: the Web Storage `storage` event only fires for *other*
 * tabs, so we can't rely on it. Instead we maintain a [MutableStateFlow] and
 * re-emit after every [applyBatch] or [clear].
 */
@PublishedApi
internal class LocalStorageStorage(
    private val storagePrefix: String,
) : KSafePlatformStorage {

    private val changes = MutableStateFlow<Map<String, StoredValue>>(readSnapshotSync())

    override suspend fun snapshot(): Map<String, StoredValue> = readSnapshotSync()

    override fun snapshotFlow(): Flow<Map<String, StoredValue>> = changes.asStateFlow()

    override suspend fun applyBatch(ops: List<StorageOp>) {
        if (ops.isEmpty()) return
        for (op in ops) when (op) {
            is StorageOp.Put -> safeLocalStorageSet(storagePrefix + op.rawKey, op.value.asString())
            is StorageOp.Delete -> localStorageRemove(storagePrefix + op.rawKey)
        }
        changes.value = readSnapshotSync()
        // Browsers are single-threaded: without yielding, downstream
        // collectors (Flow/StateFlow observers) don't run until the current
        // coroutine fully returns. Tests call `put()` and immediately
        // subscribe — they need the collector to have already propagated the
        // new value by then. `yield()` gives the event loop a tick.
        yield()
    }

    /** Catches QuotaExceededError and rethrows with actionable context. */
    private fun safeLocalStorageSet(key: String, value: String) {
        try {
            localStorageSet(key, value)
        } catch (e: Throwable) {
            throw IllegalStateException(
                "KSafe: localStorage quota exceeded. " +
                    "localStorage is limited to ~5-10MB per origin. " +
                    "Consider reducing stored data or using fewer keys.",
                e,
            )
        }
    }

    override suspend fun clear() {
        val keysToRemove = buildList {
            for (i in 0 until localStorageLength()) {
                localStorageKey(i)?.takeIf { it.startsWith(storagePrefix) }?.let(::add)
            }
        }
        keysToRemove.forEach(::localStorageRemove)
        changes.value = emptyMap()
    }

    /**
     * localStorage stores only strings, so every [StoredValue] collapses to its
     * `.toString()` here. The core re-types the read value through the
     * request's serializer on the way back up.
     */
    private fun StoredValue.asString(): String = when (this) {
        is StoredValue.BoolVal -> value.toString()
        is StoredValue.IntVal -> value.toString()
        is StoredValue.LongVal -> value.toString()
        is StoredValue.FloatVal -> value.toString()
        is StoredValue.DoubleVal -> value.toString()
        is StoredValue.Text -> value
    }

    private fun readSnapshotSync(): Map<String, StoredValue> {
        val out = HashMap<String, StoredValue>()
        val len = localStorageLength()
        for (i in 0 until len) {
            val fullKey = localStorageKey(i) ?: continue
            if (!fullKey.startsWith(storagePrefix)) continue
            val short = fullKey.removePrefix(storagePrefix)
            val value = localStorageGet(fullKey) ?: continue
            // Reads always return Text — primitives survive because the core
            // converts using the requested serializer's primitive kind.
            out[short] = StoredValue.Text(value)
        }
        return out
    }
}
