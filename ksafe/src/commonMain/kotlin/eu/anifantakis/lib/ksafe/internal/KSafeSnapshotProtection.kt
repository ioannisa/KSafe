package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeProtection

/**
 * User key → recorded protection off a raw snapshot, with [KeySafeMetadataManager.collectMetadata]'s
 * canonical-over-legacy rule; the core and Apple sweeps must reap and keep the same entries.
 */
internal fun protectionByKeyFromSnapshot(
    snapshot: Map<String, StoredValue>,
): Map<String, KSafeProtection> {
    val entries = snapshot.mapNotNull { (rawKey, value) -> (value as? StoredValue.Text)?.let { rawKey to it.value } }
    val out = mutableMapOf<String, KSafeProtection>()
    for ((userKey, literal) in KeySafeMetadataManager.collectMetadata(entries)) {
        KeySafeMetadataManager.parseProtection(literal)?.let { out[userKey] = it }
    }
    return out
}
