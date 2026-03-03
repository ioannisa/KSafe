package eu.anifantakis.lib.ksafe

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Shared key/metadata helpers used across platform implementations.
 *
 * Keep key-shape and metadata parsing logic centralized so platform files
 * only handle storage/encryption specifics.
 */
@PublishedApi
internal object KeySafeMetadataManager {
    @PublishedApi
    internal const val LEGACY_ENCRYPTED_PREFIX = "encrypted_"
    @PublishedApi
    internal const val LEGACY_PROTECTION_PREFIX = "__ksafe_prot_"
    @PublishedApi
    internal const val LEGACY_PROTECTION_SUFFIX = "__"

    // Reserved for the unified key scheme migration path.
    @PublishedApi
    internal const val VALUE_PREFIX = "__ksafe_value_"
    @PublishedApi
    internal const val META_PREFIX = "__ksafe_meta_"
    @PublishedApi
    internal const val META_SUFFIX = "__"
    @PublishedApi
    internal const val ACCESS_POLICY_UNLOCKED = "unlocked"

    @PublishedApi
    internal fun legacyEncryptedRawKey(key: String): String = "$LEGACY_ENCRYPTED_PREFIX$key"

    @PublishedApi
    internal fun legacyProtectionRawKey(key: String): String =
        "$LEGACY_PROTECTION_PREFIX$key$LEGACY_PROTECTION_SUFFIX"

    @PublishedApi
    internal fun valueRawKey(key: String): String = "$VALUE_PREFIX$key"

    @PublishedApi
    internal fun metadataRawKey(key: String): String = "$META_PREFIX$key$META_SUFFIX"

    @PublishedApi
    internal fun tryExtractLegacyProtectionKey(rawKey: String): String? {
        return if (rawKey.startsWith(LEGACY_PROTECTION_PREFIX) && rawKey.endsWith(LEGACY_PROTECTION_SUFFIX)) {
            rawKey.removePrefix(LEGACY_PROTECTION_PREFIX).removeSuffix(LEGACY_PROTECTION_SUFFIX)
        } else null
    }

    @PublishedApi
    internal fun tryExtractLegacyEncryptedKey(rawKey: String): String? {
        return if (rawKey.startsWith(LEGACY_ENCRYPTED_PREFIX)) {
            rawKey.removePrefix(LEGACY_ENCRYPTED_PREFIX)
        } else null
    }

    @PublishedApi
    internal fun tryExtractCanonicalMetadataKey(rawKey: String): String? {
        return if (rawKey.startsWith(META_PREFIX) && rawKey.endsWith(META_SUFFIX)) {
            rawKey.removePrefix(META_PREFIX).removeSuffix(META_SUFFIX)
        } else null
    }

    @PublishedApi
    internal fun tryExtractCanonicalValueKey(rawKey: String): String? {
        return if (rawKey.startsWith(VALUE_PREFIX)) {
            rawKey.removePrefix(VALUE_PREFIX)
        } else null
    }

    @PublishedApi
    internal fun isInternalStorageKey(rawKey: String): Boolean {
        return rawKey.startsWith("__ksafe_") || rawKey.startsWith("ksafe_")
    }

    @PublishedApi
    internal data class ClassifiedStorageEntry(
        val userKey: String,
        val cacheKey: String,
        val encrypted: Boolean
    )

    /**
     * Collects per-key metadata from canonical and legacy metadata entries.
     *
     * Canonical entries (`__ksafe_meta_*__`) always win over legacy metadata.
     */
    @PublishedApi
    internal fun collectMetadata(
        entries: Iterable<Pair<String, String?>>,
        accept: (String) -> Boolean = { true }
    ): Map<String, String> {
        val canonical = mutableMapOf<String, String>()
        val legacy = mutableMapOf<String, String>()

        for ((rawKey, rawValue) in entries) {
            val value = rawValue ?: continue

            val canonicalKey = tryExtractCanonicalMetadataKey(rawKey)
            if (canonicalKey != null) {
                if (accept(canonicalKey)) {
                    canonical[canonicalKey] = value
                }
                continue
            }

            val legacyKey = tryExtractLegacyProtectionKey(rawKey)
            if (legacyKey != null) {
                if (accept(legacyKey) && !canonical.containsKey(legacyKey)) {
                    legacy[legacyKey] = value
                }
            }
        }

        val merged = mutableMapOf<String, String>()
        merged.putAll(canonical)
        for ((k, v) in legacy) {
            if (!merged.containsKey(k)) {
                merged[k] = v
            }
        }
        return merged
    }

    /**
     * Classifies a persisted key/value entry and resolves where it should live in memory cache.
     *
     * Returns `null` for internal metadata keys that are not user values.
     */
    @PublishedApi
    internal fun classifyStorageEntry(
        rawKey: String,
        legacyEncryptedPrefix: String,
        encryptedCacheKeyForUser: (String) -> String,
        stagedMetadata: Map<String, String>,
        existingMetadata: Map<String, String>
    ): ClassifiedStorageEntry? {
        val canonicalUserKey = tryExtractCanonicalValueKey(rawKey)
        if (canonicalUserKey != null) {
            val rawMeta = stagedMetadata[canonicalUserKey] ?: existingMetadata[canonicalUserKey]
            val isEncrypted = parseProtection(rawMeta) != null
            val cacheKey = if (isEncrypted) encryptedCacheKeyForUser(canonicalUserKey) else canonicalUserKey
            return ClassifiedStorageEntry(canonicalUserKey, cacheKey, isEncrypted)
        }

        if (rawKey.startsWith(legacyEncryptedPrefix)) {
            val userKey = rawKey.removePrefix(legacyEncryptedPrefix)
            return ClassifiedStorageEntry(userKey, encryptedCacheKeyForUser(userKey), true)
        }

        if (isInternalStorageKey(rawKey)) {
            return null
        }

        return ClassifiedStorageEntry(rawKey, rawKey, false)
    }

    /**
     * Parses protection from either:
     * 1) legacy literal values ("NONE", "DEFAULT", "HARDWARE_ISOLATED"), or
     * 2) metadata JSON payload containing field `p`.
     */
    @PublishedApi
    internal fun parseProtection(raw: String?): KSafeProtection? {
        if (raw == null) return null

        when (raw) {
            "NONE" -> return null
            "DEFAULT" -> return KSafeProtection.DEFAULT
            "HARDWARE_ISOLATED" -> return KSafeProtection.HARDWARE_ISOLATED
        }

        return try {
            when (KSafeJson.codec.parseToJsonElement(raw).jsonObject["p"]?.jsonPrimitive?.content) {
                "NONE" -> null
                "DEFAULT" -> KSafeProtection.DEFAULT
                "HARDWARE_ISOLATED" -> KSafeProtection.HARDWARE_ISOLATED
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Parses per-key access policy from metadata JSON field `u`.
     *
     * Legacy metadata (`__ksafe_prot_*__`) has no `u` and returns null.
     */
    @PublishedApi
    internal fun parseAccessPolicy(raw: String?): String? {
        if (raw == null) return null
        return try {
            KSafeJson.codec.parseToJsonElement(raw).jsonObject["u"]?.jsonPrimitive?.content
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Builds compact metadata JSON payload.
     */
    @PublishedApi
    internal fun buildMetadataJson(
        protection: KSafeProtection?,
        accessPolicy: String?
    ): String {
        val payload = buildJsonObject {
            put("v", 1)
            put(
                "p",
                when (protection) {
                    null -> "NONE"
                    KSafeProtection.DEFAULT -> "DEFAULT"
                    KSafeProtection.HARDWARE_ISOLATED -> "HARDWARE_ISOLATED"
                }
            )
            if (!accessPolicy.isNullOrEmpty()) put("u", accessPolicy)
        }
        return payload.toString()
    }

    @PublishedApi
    internal fun accessPolicyFor(requireUnlockedDevice: Boolean): String? {
        return if (requireUnlockedDevice) ACCESS_POLICY_UNLOCKED else null
    }
}

/**
 * Local shared JSON codec for helper parsing/encoding.
 */
internal object KSafeJson {
    val codec = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
}
