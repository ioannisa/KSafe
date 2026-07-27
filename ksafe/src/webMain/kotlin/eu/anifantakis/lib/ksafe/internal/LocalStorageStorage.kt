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
    /**
     * The one-time migration done-markers gating copy-forwards INTO this store from retained
     * sources (they live outside [storagePrefix], see the factory). [clear] seals them: an
     * explicit wipe means the user chose an empty store, so a marker whose original write
     * failed (quota/SecurityError) must not let the still-present source re-seed the wiped
     * data on the next construction.
     */
    private val migrationMarkersSealedOnClear: List<String> = emptyList(),
) : KSafePlatformStorage {

    private val changes = MutableStateFlow<Map<String, StoredValue>>(readSnapshotSync())

    override suspend fun snapshot(): Map<String, StoredValue> = readSnapshotSync()

    override fun snapshotFlow(): Flow<Map<String, StoredValue>> = changes.asStateFlow()

    override suspend fun applyBatch(ops: List<StorageOp>) {
        if (ops.isEmpty()) return
        // localStorage has no transaction API. A synchronous mid-batch failure (usually
        // QuotaExceededError) is rolled back below. Writes are ordered metadata-before-value so a
        // crash leaves metadata without its value (reads fall back to the default via
        // classifyStorageEntry, never raw ciphertext) rather than a value without metadata.
        val ordered = orderMetaBeforeValue(ops)
        val priors = HashMap<String, String?>()
        for (op in ordered) {
            val fullKey = storagePrefix + op.rawKey
            if (fullKey !in priors) priors[fullKey] = localStorageGet(fullKey)
        }
        try {
            for (op in ordered) when (op) {
                is StorageOp.Put -> safeLocalStorageSet(storagePrefix + op.rawKey, op.value.asString())
                is StorageOp.Delete -> localStorageRemove(storagePrefix + op.rawKey)
            }
        } catch (e: Throwable) {
            try {
                rollbackPriors(priors, ::localStorageSet, ::localStorageRemove)
            } catch (rollbackError: Throwable) {
                // A rollback that couldn't fully restore means silent data loss; surface it with
                // the original write failure attached.
                rollbackError.addSuppressed(e)
                throw rollbackError
            }
            throw e
        } finally {
            changes.value = readSnapshotSync()
            // Single-threaded browsers: without a yield, a put()-then-subscribe wouldn't see the
            // new value until this coroutine returns.
            yield()
        }
    }

    // Deletes first, then metadata Puts, then value Puts, so a process death mid-batch can't leave a
    // value persisted ahead of its metadata. Stable within each group.
    private fun orderMetaBeforeValue(ops: List<StorageOp>): List<StorageOp> =
        ops.sortedBy { op ->
            when {
                op is StorageOp.Delete -> 0
                op is StorageOp.Put &&
                    KeySafeMetadataManager.tryExtractCanonicalValueKey(op.rawKey) != null -> 2
                else -> 1
            }
        }

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
        // Seal BEFORE the wipe so a crash mid-clear can't leave the store half-wiped AND
        // re-seedable; repeated after it for the rare set() that failed on a full quota
        // (the wipe just freed space). Best-effort: a markerless clear still wipes.
        sealMigrationMarkers()
        val keysToRemove = buildList {
            for (i in 0 until localStorageLength()) {
                localStorageKey(i)?.takeIf { it.startsWith(storagePrefix) }?.let(::add)
            }
        }
        keysToRemove.forEach(::localStorageRemove)
        sealMigrationMarkers()
        changes.value = emptyMap()
    }

    private fun sealMigrationMarkers() {
        for (marker in migrationMarkersSealedOnClear) {
            runCatching { localStorageSet(marker, "1") }
        }
    }

    private fun readSnapshotSync(): Map<String, StoredValue> {
        val out = HashMap<String, StoredValue>()
        val len = localStorageLength()
        for (i in 0 until len) {
            val fullKey = localStorageKey(i) ?: continue
            if (!fullKey.startsWith(storagePrefix)) continue
            val short = fullKey.removePrefix(storagePrefix)
            val value = localStorageGet(fullKey) ?: continue
            // Always Text; primitives are re-typed by the core's serializer on read.
            out[short] = StoredValue.Text(value)
        }
        return out
    }
}

/**
 * One-time migration of a store's data entries from the legacy `ksafe_<name>_…` namespace to the
 * prefix-free `ksafe.<name>:…` one.
 *
 * Only canonical entries (remainder starts with `__ksafe_`) move — that gate keeps the migration
 * order-independent for nested store names and leaves non-canonical engine key records untouched.
 *
 * Copy-if-absent then delete: the source is cleared only once the destination holds the value, so a
 * mid-migration failure retries later and never loses the only copy.
 *
 * Returns `true` only when every required copy is verifiably present at the destination, so
 * callers gating a one-time done-marker on the result never seal a partially failed migration
 * (e.g. a quota failure on one large value) behind a marker that prevents any retry.
 */
internal fun migrateLegacyLocalStoragePrefix(oldPrefix: String, newPrefix: String, deleteSource: Boolean = true): Boolean {
    val keys = buildList {
        for (i in 0 until localStorageLength()) {
            localStorageKey(i)?.takeIf { it.startsWith(oldPrefix) }?.let(::add)
        }
    }
    return migratePrefixedEntries(
        keys, oldPrefix, newPrefix, deleteSource,
        ::localStorageGet, ::localStorageSet, ::localStorageRemove,
    )
}

/**
 * Copy loop of [migrateLegacyLocalStoragePrefix], pure over [get]/[set]/[remove] so partial-failure
 * behavior is testable without a real `localStorage` (mirroring [rollbackPriors]). Returns `true`
 * only when every canonical entry in [sourceKeys] is verifiably present at the destination;
 * skipped non-canonical entries and vanished sources count as success.
 */
internal fun migratePrefixedEntries(
    sourceKeys: List<String>,
    oldPrefix: String,
    newPrefix: String,
    deleteSource: Boolean,
    get: (String) -> String?,
    set: (String, String) -> Unit,
    remove: (String) -> Unit,
): Boolean {
    var allCopied = true
    for (oldKey in sourceKeys) {
        val rest = oldKey.removePrefix(oldPrefix)
        // Legacy 1.6/1.7 flat entries (`<key>` / `encrypted_<key>`) carry no canonical marker, so a
        // shorter-named store can't tell its own flat key from a nested sibling's; migrating them
        // would steal the sibling's only copy. Left untouched until a scheme can disambiguate.
        if (!rest.startsWith(KSAFE_RESERVED_NAMESPACE_PREFIX)) continue
        val value = get(oldKey) ?: continue
        val newKey = newPrefix + rest
        if (get(newKey) == null) {
            runCatching { set(newKey, value) }
        }
        val copied = get(newKey) != null
        if (!copied) allCopied = false
        // For the appNamespace upgrade the source prefix is also the live prefix of a co-existing
        // no-namespace store on the same fileName; deleting it would cannibalize that sibling's
        // writes on every construction. Copy-if-absent + no-delete is idempotent.
        if (deleteSource && copied) {
            runCatching { remove(oldKey) }
        }
    }
    return allCopied
}

/**
 * Restores the pre-batch state in [priors] (full key → prior value, or `null` if absent) after an
 * [LocalStorageStorage.applyBatch] failure. Pure over [set]/[remove] so it's testable without a real
 * `localStorage`.
 *
 * All touched keys are removed first — freeing the space the partial batch consumed — before priors
 * are restored, so a restore can't hit the same quota that failed the batch. A failed restore is
 * surfaced, not swallowed.
 */
internal fun rollbackPriors(
    priors: Map<String, String?>,
    set: (String, String) -> Unit,
    remove: (String) -> Unit,
) {
    for (fullKey in priors.keys) {
        runCatching { remove(fullKey) }
    }
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
