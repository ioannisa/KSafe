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
 * Derives both identities from the store's path spellings, most-resolved first: the real pair
 * (links resolved where the platform can), the canonical pair (symlinks and relative segments, so
 * identity survives a relocated home), then the raw pair. The identity is the first spelling; the
 * fallback is the first older spelling that differs, since an earlier build bound the store to the
 * best one it could derive.
 */
internal fun resolveStoreIdentity(
    canonicalPath: String,
    canonicalHome: String?,
    rawPath: String,
    rawHome: String?,
    realPath: String? = null,
    realHome: String? = null,
): StoreIdentity {
    val spellings = buildList {
        if (realPath != null) add(realPath to realHome)
        add(canonicalPath to canonicalHome)
        add(rawPath to rawHome)
    }
    val identities = spellings.map { (path, home) -> KeySafeMetadataManager.stableStoreIdentity(path, home) }
    val canonical = identities.first()
    // Only one fallback slot exists, so the nearer spelling wins: a raw-bound entry needs a lost
    // canonicalization AND a link, which no session has been seen to produce.
    return StoreIdentity(canonical, identities.drop(1).firstOrNull { it != canonical }.orEmpty())
}
