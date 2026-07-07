package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.yield

/**
 * [KSafePlatformStorage] over the browser's `localStorage`, which is synchronous and string-only:
 * every [StoredValue] flattens to `.toString()` on write and the core re-types it through the
 * request's serializer on read. Keys are prefixed with [storagePrefix] so instances with
 * different `fileName`s don't collide.
 *
 * The Web Storage `storage` event only fires for other tabs, so change observation instead
 * re-emits a [MutableStateFlow] after every [applyBatch] or [clear].
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
        // localStorage has no transaction API, so emulate all-or-nothing: snapshot every key the
        // batch touches and restore on failure (typically QuotaExceededError mid-batch). Otherwise
        // a partial batch can persist a value without its metadata, which a later read
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
            try {
                rollbackPriors(priors, ::localStorageSet, ::localStorageRemove)
            } catch (rollbackError: Throwable) {
                // A rollback that couldn't fully restore is worse than the write failure (silent
                // data loss); surface it with the original write failure attached.
                rollbackError.addSuppressed(e)
                throw rollbackError
            }
            throw e
        } finally {
            changes.value = readSnapshotSync()
            // Single-threaded browsers: without a yield, collectors don't run until this coroutine
            // returns, so a put()-then-subscribe wouldn't see the new value yet.
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

    /** localStorage is string-only; every [StoredValue] collapses to `.toString()` here. */
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
            // Always Text; primitives survive via the core's serializer-driven conversion.
            out[short] = StoredValue.Text(value)
        }
        return out
    }
}

/**
 * One-time migration of a store's data entries from the legacy `ksafe_<name>_…` namespace to the
 * prefix-free `ksafe.<name>:…` one.
 *
 * Only canonical entries (remainder starts with `__ksafe_`) move. That gate keeps the migration
 * order-independent for nested store names: store "user" scanning `ksafe_user_cache___ksafe_value_x`
 * sees the non-canonical remainder `cache___ksafe_value_x` and leaves it for store "user_cache".
 * Engine key records (`…ksafe_key_<alias>`) aren't canonical-shaped and stay put.
 *
 * Copy-if-absent then delete: the source is cleared only once the destination verifiably holds the
 * value, so a mid-migration failure (e.g. quota) retries later and never loses the only copy.
 */
internal fun migrateLegacyLocalStoragePrefix(oldPrefix: String, newPrefix: String, deleteSource: Boolean = true) {
    val keys = buildList {
        for (i in 0 until localStorageLength()) {
            localStorageKey(i)?.takeIf { it.startsWith(oldPrefix) }?.let(::add)
        }
    }
    for (oldKey in keys) {
        val rest = oldKey.removePrefix(oldPrefix)
        // Only canonical entries migrate (gate explained above). Legacy 1.6/1.7 FLAT entries
        // (bare `<key>` / `encrypted_<key>`) carry no canonical marker, so a shorter-named store
        // can't tell its own flat key from a nested sibling's; migrating them would steal the
        // sibling's only copy and surface it under the wrong store. They're left untouched
        // (orphaned-but-private, recoverable) until a scheme can disambiguate nested names.
        if (!rest.startsWith("__ksafe_")) continue
        val value = localStorageGet(oldKey) ?: continue
        val newKey = newPrefix + rest
        if (localStorageGet(newKey) == null) {
            runCatching { localStorageSet(newKey, value) }
        }
        // Delete the source only when [deleteSource]. For the appNamespace upgrade the source
        // prefix `ksafe.<file>:` is also the live prefix of a co-existing no-namespace store on the
        // same fileName; deleting it would cannibalize that sibling's writes on every construction.
        // Copy-if-absent + no-delete is idempotent; the only cost is a harmless orphaned copy under
        // the old prefix after a genuine one-way upgrade.
        if (deleteSource && localStorageGet(newKey) != null) {
            runCatching { localStorageRemove(oldKey) }
        }
    }
}

/**
 * Restores the pre-batch state in [priors] (full key → prior value, or `null` if absent) after an
 * [LocalStorageStorage.applyBatch] failure. Pure over [set]/[remove] so the ordering and failure
 * contract are testable without a real `localStorage`.
 *
 * Order matters: all touched keys are removed first — freeing the space the partial batch
 * consumed — before priors are restored, so a restore can't hit the same quota that failed the
 * batch. A restore that still fails is surfaced, not swallowed.
 */
internal fun rollbackPriors(
    priors: Map<String, String?>,
    set: (String, String) -> Unit,
    remove: (String) -> Unit,
) {
    // Free all space the partial batch consumed before restoring anything.
    for (fullKey in priors.keys) {
        runCatching { remove(fullKey) }
    }
    // Restore prior values; collect (don't swallow) any that still fail.
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
