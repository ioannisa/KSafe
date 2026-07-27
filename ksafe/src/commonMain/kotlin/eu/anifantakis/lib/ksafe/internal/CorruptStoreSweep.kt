package eu.anifantakis.lib.ksafe.internal

/**
 * Marks the copy a store's corruption handler sets aside before it continues from empty. Both the
 * writer that names the copy and the `clearAll()` sweep that finds it derive their spelling from
 * here: spelled independently, a writer and a sweep drift and the sweep silently stops matching.
 */
private const val CORRUPT_QUARANTINE_MARKER = ".corrupt"

/**
 * The quarantine name for the store file (or full path) [store] — also the prefix every timestamped
 * quarantine copy starts with, which is what [sweepCorruptQuarantineCopies] matches on.
 */
internal fun corruptQuarantineName(store: String): String = "$store$CORRUPT_QUARANTINE_MARKER"

/**
 * What a TIMESTAMPED quarantine copy carries between the store name and the stamp. Exposed
 * because the JVM residual-file sweep matches quarantine copies by infix rather than by store
 * prefix, and must not spell the marker a second time.
 */
internal const val CORRUPT_QUARANTINE_TIMESTAMP_INFIX: String = "$CORRUPT_QUARANTINE_MARKER-"

/** As [corruptQuarantineName], stamped with [nowMillis] so successive corruptions don't collide. */
internal fun corruptQuarantineName(store: String, nowMillis: Long): String =
    "$store$CORRUPT_QUARANTINE_TIMESTAMP_INFIX$nowMillis"

/**
 * Deletes every quarantine copy of [storeFileName]. Each still holds decryptable ciphertext, so a
 * copy left behind turns a total wipe into a partial one — every platform whose corruption handler
 * quarantines must run this from its `clearAll()` cleanup.
 *
 * Matched on the store's own file name, so a sibling safe in the same directory is never touched,
 * and on the bare marker rather than the timestamped form, so a fixed-name copy is swept too. The
 * live store file is deliberately left alone: the core already emptied it on its write consumer,
 * and deleting it from the caller thread would race a concurrent commit.
 *
 * Best-effort throughout — a wipe must not fail because one file could not be listed or deleted.
 */
internal fun sweepCorruptQuarantineCopies(
    storeFileName: String,
    listNames: () -> List<String>,
    delete: (String) -> Unit,
) {
    runCatching {
        val prefix = corruptQuarantineName(storeFileName)
        for (name in listNames()) {
            if (name.startsWith(prefix)) runCatching { delete(name) }
        }
    }
}
