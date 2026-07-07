package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeProtection
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Key-shape and metadata parsing helpers shared by the platform implementations. */
@PublishedApi
internal object KeySafeMetadataManager {
    @PublishedApi
    internal const val LEGACY_ENCRYPTED_PREFIX = "encrypted_"
    @PublishedApi
    internal const val LEGACY_PROTECTION_PREFIX = "__ksafe_prot_"
    @PublishedApi
    internal const val LEGACY_PROTECTION_SUFFIX = "__"

    @PublishedApi
    internal const val VALUE_PREFIX = "__ksafe_value_"
    @PublishedApi
    internal const val META_PREFIX = "__ksafe_meta_"
    @PublishedApi
    internal const val META_SUFFIX = "__"
    @PublishedApi
    internal const val ACCESS_POLICY_UNLOCKED = "unlocked"

    // Metadata `v` field: v1 (legacy) ciphertext uses a per-entry key alias derived
    // from the user key; v2 DEFAULT entries use the datastore master key (locked or
    // unlocked per the `u` field) while HARDWARE_ISOLATED keeps the per-entry alias.
    // No on-disk migration: v1 entries stay v1 until overwritten via the v2 path.
    @PublishedApi
    internal const val ENVELOPE_VERSION_V1 = 1
    @PublishedApi
    internal const val ENVELOPE_VERSION_V2 = 2
    @PublishedApi
    internal const val ENVELOPE_VERSION_LATEST = ENVELOPE_VERSION_V2

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
        // `__ksafe_` is the KSafe-reserved namespace; `ksafe_key_` is the web engine's
        // legacy localStorage key store. Match only these — a blanket `ksafe_` match
        // would swallow user keys that merely start with "ksafe_".
        return rawKey.startsWith("__ksafe_") || rawKey.startsWith("ksafe_key_")
    }

    @PublishedApi
    internal data class ClassifiedStorageEntry(
        val userKey: String,
        val cacheKey: String,
        val encrypted: Boolean
    )

    /** Collects per-key metadata; canonical entries (`__ksafe_meta_*__`) win over legacy ones. */
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

    /** Classifies a persisted entry and resolves its cache key; `null` for internal non-value keys. */
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

    @PublishedApi
    internal fun protectionToLiteral(protection: KSafeProtection?): String = when (protection) {
        null -> "NONE"
        KSafeProtection.DEFAULT -> "DEFAULT"
        KSafeProtection.HARDWARE_ISOLATED -> "HARDWARE_ISOLATED"
    }

    /** Extracts the protection literal from raw metadata (JSON `p` field or legacy literal). */
    @PublishedApi
    internal fun extractProtectionLiteral(rawMetadata: String): String {
        when (rawMetadata) {
            "NONE", "DEFAULT", "HARDWARE_ISOLATED" -> return rawMetadata
        }
        return try {
            KSafeJson.codec.parseToJsonElement(rawMetadata)
                .jsonObject["p"]?.jsonPrimitive?.content ?: "NONE"
        } catch (_: Exception) { "NONE" }
    }

    /** Parses protection from a legacy literal or the metadata JSON `p` field. */
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

    /** Parses the access policy from the metadata JSON `u` field; legacy metadata has none. */
    @PublishedApi
    internal fun parseAccessPolicy(raw: String?): String? {
        if (raw == null) return null
        return try {
            KSafeJson.codec.parseToJsonElement(raw).jsonObject["u"]?.jsonPrimitive?.content
        } catch (_: Exception) {
            null
        }
    }

    /** Builds the metadata JSON payload; tests may pass [ENVELOPE_VERSION_V1] to fabricate legacy entries. */
    @PublishedApi
    internal fun buildMetadataJson(
        protection: KSafeProtection?,
        accessPolicy: String?,
        envelopeVersion: Int = ENVELOPE_VERSION_LATEST,
    ): String {
        val payload = buildJsonObject {
            put("v", envelopeVersion)
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

    /** Envelope version from raw metadata; anything legacy or unparseable is [ENVELOPE_VERSION_V1]. */
    @PublishedApi
    internal fun parseEnvelopeVersion(raw: String?): Int {
        if (raw == null) return ENVELOPE_VERSION_V1
        when (raw) {
            "NONE", "DEFAULT", "HARDWARE_ISOLATED" -> return ENVELOPE_VERSION_V1
        }
        return try {
            KSafeJson.codec.parseToJsonElement(raw)
                .jsonObject["v"]?.jsonPrimitive?.content?.toIntOrNull()
                ?: ENVELOPE_VERSION_V1
        } catch (_: Exception) {
            ENVELOPE_VERSION_V1
        }
    }

    @PublishedApi
    internal fun parseRequireUnlockedDevice(raw: String?): Boolean {
        return parseAccessPolicy(raw) == ACCESS_POLICY_UNLOCKED
    }

    @PublishedApi
    internal fun accessPolicyFor(requireUnlockedDevice: Boolean): String? {
        return if (requireUnlockedDevice) ACCESS_POLICY_UNLOCKED else null
    }
}

internal object KSafeJson {
    val codec = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
}
