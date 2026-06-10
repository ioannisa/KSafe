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
        // localStorage has no transaction API, so emulate the all-or-nothing
        // semantics the DataStore backends get from `edit {}`: snapshot the prior
        // value of every key the batch touches, and on any failure (typically a
        // QuotaExceededError mid-batch) restore them. Without this a partial batch
        // can persist a value without its metadata — which a later read
        // misclassifies as plaintext and hands back as the raw ciphertext string.
        val priors = HashMap<String, String?>()
        for (op in ops) {
            val fullKey = storagePrefix + op.rawKey
            if (fullKey !in priors) priors[fullKey] = localStorageGet(fullKey)
        }
        try {
            for (op in ops) when (op) {
                is StorageOp.Put -> safeLocalStorageSet(storagePrefix + op.rawKey, op.value.asString())
                is StorageOp.Delete -> localStorageRemove(storagePrefix + op.rawKey)
            }
        } catch (e: Throwable) {
            // Roll back to the pre-batch state. See [rollbackPriors] for why the
            // order matters (removals first) and why a failed restore must be
            // surfaced rather than swallowed (deep-review #38).
            try {
                rollbackPriors(priors, ::localStorageSet, ::localStorageRemove)
            } catch (rollbackError: Throwable) {
                // The rollback itself could not fully restore — strictly worse
                // than the original write failure (silent data loss), and the
                // caller must hear about it instead of being told the batch
                // atomically failed with nothing changed. Surface it, keeping
                // the original write failure attached.
                rollbackError.addSuppressed(e)
                throw rollbackError
            }
            throw e
        } finally {
            // Re-emit on both success (new state) and failure (rolled-back state).
            changes.value = readSnapshotSync()
            // Browsers are single-threaded: without yielding, downstream
            // collectors (Flow/StateFlow observers) don't run until the current
            // coroutine fully returns. Tests call `put()` and immediately
            // subscribe — they need the collector to have already propagated the
            // new value by then. `yield()` gives the event loop a tick.
            yield()
        }
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

/**
 * Restores the pre-batch state captured in [priors] (full key → prior value, or
 * `null` if the key did not exist) after an [LocalStorageStorage.applyBatch]
 * failure. Extracted as a pure function over [set]/[remove] so the order and
 * failure-handling contract can be tested without a real `localStorage`.
 *
 * Two things the naive `for ((k, v) in priors) { set-or-remove }` got wrong
 * (deep-review #38):
 *
 *  1. **Order.** A coalesced batch routinely mixes Deletes and Puts of different
 *     keys (every write also emits legacy-key Deletes, and a ~16 ms window
 *     coalesces unrelated keys). Restoring in arbitrary [Map] iteration order can
 *     try to re-add a large *deleted* key's value BEFORE removing a *newly put*
 *     key that consumed the freed space — that `set` then hits the very quota
 *     that failed the batch, and the deleted key's prior value is lost. So we
 *     **remove every touched key first** (freeing all the space the partial
 *     batch consumed), then restore the non-null priors; since those values fit
 *     before the batch ran, they fit again.
 *  2. **Swallowed failures.** A restore that still fails was caught and ignored,
 *     so the caller was told the batch atomically failed (nothing changed) while
 *     a key was actually gone. Any restore failure is now collected and
 *     surfaced.
 */
internal fun rollbackPriors(
    priors: Map<String, String?>,
    set: (String, String) -> Unit,
    remove: (String) -> Unit,
) {
    // 1. Free all space the partial batch consumed before restoring anything.
    for (fullKey in priors.keys) {
        runCatching { remove(fullKey) }
    }
    // 2. Restore prior values; collect (don't swallow) any that still fail.
    val failures = ArrayList<Pair<String, Throwable>>()
    for ((fullKey, prior) in priors) {
        if (prior != null) {
            runCatching { set(fullKey, prior) }.onFailure { failures.add(fullKey to it) }
        }
    }
    if (failures.isNotEmpty()) {
        throw IllegalStateException(
            "KSafe: localStorage write failed and rollback could not restore " +
                "${failures.size} key(s) (${failures.joinToString { it.first }}) — " +
                "their previously stored values may be lost.",
            failures.first().second,
        )
    }
}
