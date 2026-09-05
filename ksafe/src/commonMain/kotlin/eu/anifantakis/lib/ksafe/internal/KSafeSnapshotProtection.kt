package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeProtection

/**
 * User key → recorded protection off a raw snapshot; canonical `__ksafe_meta_*__` records win over
 * legacy `__ksafe_prot_*__` ones. Shared by the core and Apple orphan sweeps: a divergent copy
 * makes one reap what the other keeps.
 */
internal fun protectionByKeyFromSnapshot(
    snapshot: Map<String, StoredValue>,
): Map<String, KSafeProtection> {
    val protectionByKey = mutableMapOf<String, KSafeProtection>()
    for ((rawKey, value) in snapshot) {
        val text = (value as? StoredValue.Text)?.value ?: continue
        KeySafeMetadataManager.tryExtractCanonicalMetadataKey(rawKey)?.let { userKey ->
            KeySafeMetadataManager.parseProtection(text)?.let { protectionByKey[userKey] = it }
            return@let
        }
        KeySafeMetadataManager.tryExtractLegacyProtectionKey(rawKey)?.let { userKey ->
            if (!protectionByKey.containsKey(userKey)) {
                KeySafeMetadataManager.parseProtection(text)?.let { protectionByKey[userKey] = it }
            }
        }
    }
    return protectionByKey
}
