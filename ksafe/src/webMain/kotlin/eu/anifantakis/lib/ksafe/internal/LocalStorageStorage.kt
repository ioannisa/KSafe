package eu.anifantakis.lib.ksafe.internal

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.yield

/**
 * [KSafePlatformStorage] over the browser's `localStorage`, keyed under [storagePrefix]. The Web
 * Storage `storage` event only fires for other tabs, so changes re-emit a [MutableStateFlow].
 */
@PublishedApi
internal class LocalStorageStorage(
    private val storagePrefix: String,
    /** Migration markers; [clear] seals them so a source can never re-seed a wiped store. */
    private val migrationMarkersSealedOnClear: List<String> = emptyList(),
) : KSafePlatformStorage {

    private val changes = MutableStateFlow<Map<String, StoredValue>>(readSnapshotSync())

    override suspend fun snapshot(): Map<String, StoredValue> = readSnapshotSync()

    override fun snapshotFlow(): Flow<Map<String, StoredValue>> = changes.asStateFlow()

    override suspend fun applyBatch(ops: List<StorageOp>) {
        if (ops.isEmpty()) return
        // localStorage has no transaction API, so a process death commits whatever part of the
        // batch already ran: clear the value slot, then write metadata, then the value, so a tear
        // leaves an entry with no value rather than one the surviving metadata decodes wrongly.
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
                // A rollback that couldn't fully restore means silent data loss; surface it.
                rollbackError.addSuppressed(e)
                throw rollbackError
            }
            throw e
        } finally {
            changes.value = readSnapshotSync()
            // Single-threaded browsers: without a yield, a put()-then-subscribe would not see the
            // new value until this coroutine returns.
            yield()
        }
    }

    internal fun orderMetaBeforeValue(ops: List<StorageOp>): List<StorageOp> =
        withValueSlotsCleared(ops).sortedBy { op ->
            when {
                op is StorageOp.Delete -> 0
                op is StorageOp.Put &&
                    KeySafeMetadataManager.tryExtractCanonicalValueKey(op.rawKey) != null -> 2
                else -> 1
            }
        }

    // Prepends a removal of every value slot this batch rewrites, so the surviving half of a tear
    // is "no value" and never the PREVIOUS value read back under the NEW metadata.
    private fun withValueSlotsCleared(ops: List<StorageOp>): List<StorageOp> {
        val rewritten = ops.mapNotNullTo(mutableSetOf()) { op ->
            (op as? StorageOp.Put)?.rawKey
                ?.takeIf { KeySafeMetadataManager.tryExtractCanonicalValueKey(it) != null }
        }
        if (rewritten.isEmpty()) return ops
        return rewritten.map { StorageOp.Delete(it) } + ops
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
        // Seal BEFORE the wipe, or a crash mid-clear leaves the store half-wiped AND re-seedable;
        // repeated after it for a set() that failed on a full quota the wipe has now freed.
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
            // localStorage is string-only; the core re-types primitives through its serializer.
            out[short] = StoredValue.Text(value)
        }
        return out
    }
}

/**
 * One-time move of a store's entries into the `ksafe.<name>:…` namespace. Copy-if-absent then
 * delete, so a failure never loses the only copy; `true` only when every copy verifiably landed.
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

/** Copy loop of [migrateLegacyLocalStoragePrefix]; `true` only when every entry verifiably landed. */
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
        // Legacy flat entries carry no canonical marker, so a shorter-named store cannot tell its
        // own key from a nested sibling's; migrating one would steal the sibling's only copy.
        if (!rest.startsWith(KSAFE_RESERVED_NAMESPACE_PREFIX)) continue
        val value = get(oldKey) ?: continue
        val newKey = newPrefix + rest
        if (get(newKey) == null) {
            runCatching { set(newKey, value) }
        }
        val copied = get(newKey) != null
        if (!copied) allCopied = false
        // The source prefix can also be the live prefix of a co-existing store; deleting from it
        // would cannibalize that store's writes on every construction — hence the opt-out.
        if (deleteSource && copied) {
            runCatching { remove(oldKey) }
        }
    }
    return allCopied
}

/**
 * Restores [priors] (full key → prior value, `null` if absent) after a failed batch. Touched keys
 * are removed first, so the restore cannot hit the same quota that failed the batch.
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
