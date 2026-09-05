package eu.anifantakis.lib.ksafe.internal

/** DataStore base file name for [fileName]. It also spells the v3 AAD store identity, so a change
 *  here re-spells every rotated entry's identity and fails its decrypt. */
internal fun dataStoreBaseFileName(fileName: String?): String =
    fileName?.let { "eu_anifantakis_ksafe_datastore_$it" } ?: "eu_anifantakis_ksafe_datastore"

/** Suffix androidx.datastore-preferences appends to [dataStoreBaseFileName]. Two string-matching
 *  consumers (the Apple quarantine sweep, the JVM copy-forward cohort) miss every file if it drifts. */
internal const val DATASTORE_FILE_SUFFIX: String = ".preferences_pb"

/** A store's v3 AAD identity ([canonical]) and the one entries carry when canonicalization failed
 *  ([fallback], blank when they agree). Decrypt retries under it, or those entries never open again. */
internal class StoreIdentity(val canonical: String, val fallback: String)

/**
 * Derives both identities: the canonical pair resolves symlinks and relative segments in path and
 * home, so identity survives an OS relocation of the home; the fallback pair resolves neither.
 */
internal fun resolveStoreIdentity(
    canonicalPath: String,
    canonicalHome: String?,
    rawPath: String,
    rawHome: String?,
): StoreIdentity {
    val canonical = KeySafeMetadataManager.stableStoreIdentity(canonicalPath, canonicalHome)
    // A session that lost only one canonicalization wrote a third, mixed spelling — not reproduced.
    val fallback = KeySafeMetadataManager.stableStoreIdentity(rawPath, rawHome)
    return StoreIdentity(canonical, fallback.takeIf { it != canonical } ?: "")
}
