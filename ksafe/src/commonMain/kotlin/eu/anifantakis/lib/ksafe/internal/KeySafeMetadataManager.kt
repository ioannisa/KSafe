package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeProtection
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * The whole vocabulary of pre-JSON (≤ 1.x) metadata: a bare protection literal, no fields.
 * [parseProtection] spells the same three in its `when`; the two must stay in step.
 */
private val LEGACY_PROTECTION_LITERALS = setOf("NONE", "DEFAULT", "HARDWARE_ISOLATED")

private fun isLegacyProtectionLiteral(raw: String): Boolean = raw in LEGACY_PROTECTION_LITERALS

/**
 * One entry's metadata parsed once, or null when it is absent, a legacy literal, or not a JSON
 * object. Every field reader's null default is right for a legacy literal; only [parseProtection]
 * and [extractProtectionLiteral] map the literal itself, and both check for it before parsing.
 */
internal fun parseMetaObject(raw: String?): JsonObject? {
    if (raw == null) return null
    if (isLegacyProtectionLiteral(raw)) return null
    return try {
        KSafeJson.codec.parseToJsonElement(raw).jsonObject
    } catch (_: Exception) {
        null
    }
}

/** Caught per field, never per record: a malformed `v` must not also blank the `g` beside it. */
private fun metaField(meta: JsonObject?, name: String): String? =
    try {
        meta?.get(name)?.jsonPrimitive?.content
    } catch (_: Exception) {
        null
    }

private fun stripAffixes(rawKey: String, prefix: String, suffix: String = ""): String? =
    if (rawKey.startsWith(prefix) && rawKey.endsWith(suffix)) {
        rawKey.removePrefix(prefix).removeSuffix(suffix)
    } else null

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
    /** Reserved plaintext entry holding key-rotation state as JSON. */
    @PublishedApi
    internal const val KEYGEN_RAW_KEY = "__ksafe_keygen__"
    @PublishedApi
    internal const val META_PREFIX = "__ksafe_meta_"
    @PublishedApi
    internal const val META_SUFFIX = "__"
    @PublishedApi
    internal const val ACCESS_POLICY_UNLOCKED = "unlocked"

    // Metadata `v`: v1 = per-entry alias derived from the user key; v2 = master key for DEFAULT,
    // per-entry alias for HARDWARE_ISOLATED; v3 = v2 routing plus the authenticated envelope
    // ([aadFor]). No on-disk migration: entries upgrade when overwritten.
    @PublishedApi
    internal const val ENVELOPE_VERSION_V1 = 1
    @PublishedApi
    internal const val ENVELOPE_VERSION_V2 = 2
    @PublishedApi
    internal const val ENVELOPE_VERSION_V3 = 3
    // Not the highest version: the default for plaintext and generation-1 writes, see envelopeVersionForWrite.
    @PublishedApi
    internal const val ENVELOPE_VERSION_LATEST = ENVELOPE_VERSION_V2

    /** Highest envelope version this build understands; `v` is unauthenticated, so a higher one fails closed. */
    @PublishedApi
    internal const val ENVELOPE_VERSION_MAX_KNOWN = ENVELOPE_VERSION_V3

    /**
     * Fails closed on a future envelope version. The message never interpolates the key and avoids
     * the "missing key" phrases the orphan sweep matches: such an entry must be preserved, not reaped.
     */
    @PublishedApi
    internal fun checkKnownEnvelopeVersion(version: Int, userKey: String) {
        check(version <= ENVELOPE_VERSION_MAX_KNOWN) {
            "KSafe: an entry records envelope version $version, newer than this KSafe " +
                "understands — refusing to decrypt it as v$ENVELOPE_VERSION_MAX_KNOWN. " +
                "The entry is preserved; upgrade KSafe to read it."
        }
    }

    /** Generation 1 stays v2 so an un-rotated store matches older releases; generation ≥ 2 writes v3. */
    @PublishedApi
    internal fun envelopeVersionForWrite(keyGeneration: Int): Int =
        if (keyGeneration >= 2) ENVELOPE_VERSION_V3 else ENVELOPE_VERSION_V2

    /**
     * Store identity for the v3 AAD, home-relative: an iOS container UUID or a JVM user home can
     * move, and an absolute path would then fail every rotated entry — the orphan sweep deletes those.
     */
    @PublishedApi
    internal fun stableStoreIdentity(fullPath: String, homePath: String?): String {
        val path = normalizeIdentitySeparators(fullPath)
        val home = homePath?.let(::normalizeIdentitySeparators)?.trimEnd('/')
        if (!home.isNullOrEmpty() && path.startsWith("$home/")) {
            return "~/" + path.removePrefix("$home/")
        }
        // Escape a literal "~/" so a caller-supplied path cannot collide with a home-relative
        // identity; the anti-transplant AAD binding depends on this staying injective.
        return if (path.startsWith("~/")) "./$path" else path
    }

    /**
     * Windows-shaped paths only: on POSIX a backslash is a legal filename character, and
     * collapsing it would merge two distinct files onto one identity.
     */
    private fun normalizeIdentitySeparators(p: String): String =
        if (p.length >= 2 && (p[1] == ':' || (p[0] == '\\' && p[1] == '\\'))) p.replace('\\', '/') else p

    /** What a v3 envelope authenticates: entry identity plus every metadata field the read path routes on. */
    @PublishedApi
    internal fun aadFor(
        storeIdentity: String,
        userKey: String,
        protection: KSafeProtection?,
        requireUnlockedDevice: Boolean,
        keyGeneration: Int,
    ): ByteArray =
        // Length-prefixed so the encoding stays injective (no delimiter collisions).
        ("ksafe.aad.v3|${storeIdentity.length}:$storeIdentity|${userKey.length}:$userKey|" +
            "${protectionToLiteral(protection)}|${if (requireUnlockedDevice) "u" else "-"}|g$keyGeneration")
            .encodeToByteArray()

    // The sentinels carry no regex metacharacters, so they interpolate into these patterns unescaped.
    private val MASTERS = "(${KSafeReservedKeys.MASTER}|${KSafeReservedKeys.MASTER_LOCKED})"

    /**
     * Master sentinels (± generation suffix), whose per-entry alias would be the store's master
     * alias. Exact match, not prefix.
     */
    private val RESERVED_USER_KEY = Regex("$MASTERS(${KSafeAliasGrammar.GENERATION_PATTERN})?")

    @PublishedApi
    internal fun isReservedUserKey(key: String): Boolean = RESERVED_USER_KEY.matches(key)

    /**
     * User keys whose trailing segment spells a reserved sentinel: their engine alias would equal a
     * store's master, a sibling's alias, or a JVM vault marker — mutating one destroys that data.
     */
    private val RESERVED_ALIAS_SUFFIX_KEY =
        // [\s\S] not `.`, which skips line terminators: a key with a newline before the sentinel
        // would slip past. The delimiter class is [.:] because JVM and web join
        // "<fileName>:<userKey>" where Android/Apple use a dot.
        Regex(
            """([\s\S]*[.:])?($MASTERS(${KSafeAliasGrammar.GENERATION_PATTERN})?""" +
                "|(${KSafeReservedKeys.STRICT_VARIANT}|${KSafeReservedKeys.ROTATED_VARIANT})" +
                "(${KSafeAliasGrammar.FINGERPRINT_PATTERN})?" +
                """|${KSafeReservedKeys.VAULT_TOMBSTONE}|${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK})"""
        )

    /**
     * A key aliasing KSafe's internal namespaces: `__ksafe_` on disk, `encrypted_` in the cache.
     * Only mutation is guarded; reads are not.
     */
    @PublishedApi
    internal fun isReservedNamespaceKey(key: String): Boolean =
        key.startsWith(RESERVED_NAMESPACE_PREFIX) || key.startsWith(LEGACY_ENCRYPTED_PREFIX)

    @PublishedApi
    internal fun requireWritableUserKey(key: String) {
        require(!isReservedNamespaceKey(key)) {
            "KSafe: '$key' uses a reserved key namespace — keys starting with " +
                "'$RESERVED_NAMESPACE_PREFIX' or '$LEGACY_ENCRYPTED_PREFIX' are reserved for " +
                "KSafe's internal storage and cache (writing one corrupts store state or " +
                "collides with an encrypted entry's cache slot). Choose a different key."
        }
        require(!RESERVED_ALIAS_SUFFIX_KEY.matches(key)) {
            "KSafe: '$key' ends in a reserved sentinel segment — its engine-key alias " +
                "would be byte-identical to a store's shared master alias or to a sibling " +
                "entry's strict per-entry alias, and mutating it could permanently destroy " +
                "that data. Choose a different key."
        }
    }

    private const val RESERVED_NAMESPACE_PREFIX = KSAFE_RESERVED_NAMESPACE_PREFIX

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
    internal fun tryExtractLegacyProtectionKey(rawKey: String): String? =
        stripAffixes(rawKey, LEGACY_PROTECTION_PREFIX, LEGACY_PROTECTION_SUFFIX)

    @PublishedApi
    internal fun tryExtractLegacyEncryptedKey(rawKey: String): String? =
        stripAffixes(rawKey, LEGACY_ENCRYPTED_PREFIX)

    @PublishedApi
    internal fun tryExtractCanonicalMetadataKey(rawKey: String): String? =
        stripAffixes(rawKey, META_PREFIX, META_SUFFIX)

    @PublishedApi
    internal fun tryExtractCanonicalValueKey(rawKey: String): String? =
        stripAffixes(rawKey, VALUE_PREFIX)

    @PublishedApi
    internal fun isInternalStorageKey(rawKey: String): Boolean {
        // Only these two (`ksafe_key_` is the web engine's legacy key store) — a blanket `ksafe_`
        // would swallow user keys starting with "ksafe_".
        return rawKey.startsWith(RESERVED_NAMESPACE_PREFIX) ||
            rawKey.startsWith(KSAFE_LEGACY_KEY_RECORD_PREFIX)
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
            // Fail-closed: absent or unparseable metadata routes through decrypt, never serving
            // ciphertext verbatim.
            val isEncrypted = isCanonicalValueEncrypted(rawMeta)
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
        if (isLegacyProtectionLiteral(rawMetadata)) return rawMetadata
        return metaField(parseMetaObject(rawMetadata), "p") ?: "NONE"
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

        return when (metaField(parseMetaObject(raw), "p")) {
            "DEFAULT" -> KSafeProtection.DEFAULT
            "HARDWARE_ISOLATED" -> KSafeProtection.HARDWARE_ISOLATED
            else -> null
        }
    }

    /**
     * Fail-closed: a canonical value entry holds plaintext or ciphertext distinguished only by
     * metadata, so anything but an explicit `NONE` routes through decrypt.
     */
    @PublishedApi
    internal fun isCanonicalValueEncrypted(rawMeta: String?): Boolean {
        if (parseProtection(rawMeta) != null) return true
        if (rawMeta == null) return true
        if (rawMeta == "NONE") return false
        return metaField(parseMetaObject(rawMeta), "p") != "NONE"
    }

    /** Birth timestamp (epoch millis) of the current key generation; null if absent or unparseable. */
    @PublishedApi
    internal fun parseKeyGenerationTimestamp(raw: String?): Long? =
        metaField(parseMetaObject(raw), "ts")?.toLongOrNull()

    /**
     * Rotation lifecycle from the generation record: `0` completed, `1` bumped but unfinished,
     * `null` no readable `r`. Any other value is unknown state and must not be reinterpreted.
     */
    internal fun parseKeyRotationLifecycle(raw: String?): Int? =
        metaField(parseMetaObject(raw), "r")?.toIntOrNull()

    /** Only an ABSENT `r` proves the old format; an unknown value must be preserved, not rewritten as completed. */
    internal fun hasKeyRotationLifecycle(raw: String?): Boolean =
        parseMetaObject(raw)?.containsKey("r") == true

    /**
     * Remaining retries after a completed rotation left retryable entries. A durable budget, not a
     * timer: a claimant writes `r:1,rp:N-1` before touching an entry, so a crash cannot restore one.
     */
    internal fun parseKeyRotationRetryAttempts(raw: String?): Int? =
        metaField(parseMetaObject(raw), "rp")
            ?.toIntOrNull()
            ?.takeIf { it >= 0 }

    /** Whether the pending-retry field exists, even if its value is unsupported. */
    internal fun hasKeyRotationRetryPending(raw: String?): Boolean =
        parseMetaObject(raw)?.containsKey("rp") == true

    /**
     * Whether `rp` is absent or a state this release owns: completed allows only a positive budget,
     * in-progress also zero, since the last attempt is decremented before its work begins.
     */
    internal fun hasSupportedKeyRotationRetryState(raw: String?): Boolean {
        if (!hasKeyRotationRetryPending(raw)) return true
        val remaining = parseKeyRotationRetryAttempts(raw) ?: return false
        return when (parseKeyRotationLifecycle(raw)) {
            0 -> remaining > 0
            1 -> true
            else -> false
        }
    }

    /**
     * Exactly the 3.0 record shape: `g` and `ts` only, both valid. A malformed record also lacks a
     * readable `r`, so it must fail closed rather than pass as migration evidence.
     */
    internal fun isLegacy30KeyGenerationState(raw: String?): Boolean {
        val meta = parseMetaObject(raw) ?: return false
        if (meta.keys != setOf("g", "ts")) return false
        val generation = metaField(meta, "g")?.toIntOrNull() ?: return false
        if (generation !in 1..MAX_KEY_GENERATION) return false
        metaField(meta, "ts")?.toLongOrNull() ?: return false
        return true
    }

    internal fun parseKeyRotationInProgress(raw: String?): Boolean =
        parseKeyRotationLifecycle(raw) == 1

    /**
     * Builds the reserved generation record. `r` is always explicit (`0` completed, `1` in
     * progress), so an absent field is unambiguously an older record; [timestampMillis] is null
     * only when repairing malformed state.
     */
    internal fun buildKeyGenerationState(
        generation: Int,
        timestampMillis: Long?,
        rotationInProgress: Boolean = false,
        retryAttemptsRemaining: Int? = null,
    ): String = buildJsonObject {
        require(retryAttemptsRemaining == null || retryAttemptsRemaining >= 0) {
            "retryAttemptsRemaining must be non-negative"
        }
        put("g", generation)
        if (timestampMillis != null) put("ts", timestampMillis)
        put("r", if (rotationInProgress) 1 else 0)
        if (retryAttemptsRemaining != null) put("rp", retryAttemptsRemaining)
    }.toString()

    /** Access policy from the metadata `u` field; legacy metadata has none. */
    @PublishedApi
    internal fun parseAccessPolicy(raw: String?): String? = accessPolicyOf(parseMetaObject(raw))

    internal fun accessPolicyOf(meta: JsonObject?): String? = metaField(meta, "u")

    /** Builds the metadata JSON payload stored beside one entry. */
    @PublishedApi
    internal fun buildMetadataJson(
        protection: KSafeProtection?,
        accessPolicy: String?,
        envelopeVersion: Int = ENVELOPE_VERSION_LATEST,
        keyGeneration: Int = 1,
        strictAliasVariant: Boolean = false,
    ): String {
        val payload = buildJsonObject {
            put("v", envelopeVersion)
            put("p", protectionToLiteral(protection))
            if (!accessPolicy.isNullOrEmpty()) put("u", accessPolicy)
            // `g` and `sa` stay omitted at their defaults: the payload then matches older releases byte for byte.
            if (keyGeneration > 1) put("g", keyGeneration)
            if (strictAliasVariant) put("sa", 1)
        }
        return payload.toString()
    }

    /**
     * The generation record is plaintext, so a fabricated huge value would drive the per-generation
     * sweep loops for billions of vault round-trips and wrap the rotation increment negative.
     */
    @PublishedApi
    internal const val MAX_KEY_GENERATION = 10_000

    /** Which alias generation decrypts the entry; legacy, missing, or unparseable is 1, and the value is clamped. */
    @PublishedApi
    internal fun parseKeyGeneration(raw: String?): Int = keyGenerationOf(parseMetaObject(raw))

    internal fun keyGenerationOf(meta: JsonObject?): Int =
        metaField(meta, "g")?.toIntOrNull()?.coerceIn(1, MAX_KEY_GENERATION) ?: 1

    /** Envelope version from raw metadata; anything legacy or unparseable is [ENVELOPE_VERSION_V1]. */
    @PublishedApi
    internal fun parseEnvelopeVersion(raw: String?): Int = envelopeVersionOf(parseMetaObject(raw))

    internal fun envelopeVersionOf(meta: JsonObject?): Int =
        metaField(meta, "v")?.toIntOrNull() ?: ENVELOPE_VERSION_V1

    @PublishedApi
    internal fun parseRequireUnlockedDevice(raw: String?): Boolean =
        requireUnlockedDeviceOf(parseMetaObject(raw))

    internal fun requireUnlockedDeviceOf(meta: JsonObject?): Boolean =
        accessPolicyOf(meta) == ACCESS_POLICY_UNLOCKED

    /** Whether the entry's key lives under the strict alias variant; absent or legacy metadata is `false`. */
    @PublishedApi
    internal fun parseStrictAliasVariant(raw: String?): Boolean =
        strictAliasVariantOf(parseMetaObject(raw))

    internal fun strictAliasVariantOf(meta: JsonObject?): Boolean =
        metaField(meta, "sa")?.toIntOrNull() == 1

    @PublishedApi
    internal fun accessPolicyFor(requireUnlockedDevice: Boolean): String? {
        return if (requireUnlockedDevice) ACCESS_POLICY_UNLOCKED else null
    }
}

internal object KSafeJson {
    val codec = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
}
