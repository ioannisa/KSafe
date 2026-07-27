package eu.anifantakis.lib.ksafe.internal

/**
 * DataStore base file name for [fileName] (the `.preferences_pb` and the JVM fallback cohort are
 * suffixed onto it). It also spells the v3 AAD store identity, so a change here re-spells every
 * rotated entry's identity and fails its decrypt.
 */
internal fun dataStoreBaseFileName(fileName: String?): String =
    fileName?.let { "eu_anifantakis_ksafe_datastore_$it" } ?: "eu_anifantakis_ksafe_datastore"

/**
 * File-name suffix androidx.datastore-preferences appends to [dataStoreBaseFileName]. Named
 * because two string-matching CONSUMERS depend on it — the Apple clearAll quarantine sweep and
 * the JVM appNamespace copy-forward cohort — and would silently miss every file if it drifted.
 */
internal const val DATASTORE_FILE_SUFFIX: String = ".preferences_pb"

/**
 * A store's v3 AAD identity ([canonical]) plus the identity its entries carry when canonicalization
 * was unavailable ([fallback], blank when the two agree), which the core retries a failed v3
 * decrypt under until a write re-binds the entry.
 *
 * [fallback] is not about older releases — v3 envelopes only exist from generation 2, so no shipped
 * build ever wrote one. It covers a divergence WITHIN a version: canonicalizing a path touches the
 * filesystem and can fail, and every caller degrades to the raw spelling when it does. Entries
 * written during such a session bind to the raw identity, and without the retry the next launch —
 * where canonicalization succeeds — would find them permanently undecryptable and silently serve
 * defaults.
 */
internal class StoreIdentity(val canonical: String, val fallback: String)

/**
 * Derives both identities from one store's path spellings.
 *
 * The canonical pair resolves symlinks / `..` / relative segments in BOTH the path and the home,
 * so one physical store keeps one identity however it was spelled, and a home-relative identity
 * survives an OS relocation of the home (iOS app-container UUID, renamed JVM account, Android
 * adoptable storage) instead of failing every rotated entry's AAD.
 *
 * The fallback pair resolves NEITHER, so it reproduces the spelling of a session that fell back on
 * both. A session that lost only ONE of the two canonicalizations wrote a third, mixed spelling
 * this does not reproduce; that is accepted rather than fixed, because the two calls resolve the
 * same directory tree and the failure would have to be transient AND harmless to the same
 * session's store I/O to strand anything.
 */
internal fun resolveStoreIdentity(
    canonicalPath: String,
    canonicalHome: String?,
    rawPath: String,
    rawHome: String?,
): StoreIdentity {
    val canonical = KeySafeMetadataManager.stableStoreIdentity(canonicalPath, canonicalHome)
    val fallback = KeySafeMetadataManager.stableStoreIdentity(rawPath, rawHome)
    return StoreIdentity(canonical, fallback.takeIf { it != canonical } ?: "")
}
