package eu.anifantakis.lib.ksafe.internal

/** Marks the copy a corruption handler sets aside. The writer that names it and the sweep that
 *  finds it must both derive the spelling here, or the sweep silently stops matching. */
private const val CORRUPT_QUARANTINE_MARKER = ".corrupt"

/** Quarantine name for [store], and the prefix every timestamped copy starts with. */
internal fun corruptQuarantineName(store: String): String = "$store$CORRUPT_QUARANTINE_MARKER"

/** What a timestamped copy carries between store name and stamp; the JVM residue sweep matches it. */
internal const val CORRUPT_QUARANTINE_TIMESTAMP_INFIX: String = "$CORRUPT_QUARANTINE_MARKER-"

/** As [corruptQuarantineName], stamped with [nowMillis] so successive corruptions don't collide. */
internal fun corruptQuarantineName(store: String, nowMillis: Long): String =
    "$store$CORRUPT_QUARANTINE_TIMESTAMP_INFIX$nowMillis"

/** Deletes every quarantine copy of [storeFileName] — each still holds decryptable ciphertext, so
 *  one left behind makes a total wipe partial. The live file stays: deleting it here races a commit. */
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
