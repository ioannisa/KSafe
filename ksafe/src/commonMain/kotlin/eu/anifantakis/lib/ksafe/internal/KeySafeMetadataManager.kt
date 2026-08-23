package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeProtection
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * The whole vocabulary of pre-JSON (≤ 1.x) metadata: a bare protection literal with no fields in
 * it. Every parser short-circuits on the same set, so a fourth literal cannot be taught to one
 * parser alone — that would leave the others returning their catch-branch default and pair, say,
 * a parsed generation with a v1 envelope on the same entry.
 */
private val LEGACY_PROTECTION_LITERALS = setOf("NONE", "DEFAULT", "HARDWARE_ISOLATED")

/**
 * A fast path, NOT a correctness guard — omitting it anywhere changes no result, only the cost.
 * None of these literals is valid JSON, so [metaField] would throw and return null, and every
 * field parser's null branch already yields the same answer this shortcut returns. What it buys
 * is skipping a thrown exception per parse on a pre-2.0 store, where these literals are the whole
 * metadata; [parseProtection] is the exception to the rule, since it MAPS the literals to values
 * rather than discarding them, so its handling is load-bearing.
 */
private fun isLegacyProtectionLiteral(raw: String): Boolean = raw in LEGACY_PROTECTION_LITERALS

/**
 * One entry's metadata parsed once, or null when it is absent, a legacy literal, or not a JSON
 * object. All three collapse because every field reader below already answers its own default
 * for all three.
 *
 * Exists so a caller wanting several fields pays one parse instead of one per field — the
 * cold-start merge reads four fields off every encrypted entry.
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

/**
 * One field of a parsed record, or null when it is absent or holds something no primitive can be
 * read from. Caught per field, never per record: a malformed `v` must not also blank the `g`
 * beside it, which is what reading each field on its own used to guarantee for free.
 */
private fun metaField(meta: JsonObject?, name: String): String? =
    try {
        meta?.get(name)?.jsonPrimitive?.content
    } catch (_: Exception) {
        null
    }

/** Strips a record-name prefix (and optional suffix) off [rawKey], or null when it doesn't carry them. */
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
    /** Reserved plaintext entry holding key-rotation state as JSON (`{"g":<generation>, ...}`), inside the `__ksafe_` namespace. */
    @PublishedApi
    internal const val KEYGEN_RAW_KEY = "__ksafe_keygen__"
    @PublishedApi
    internal const val META_PREFIX = "__ksafe_meta_"
    @PublishedApi
    internal const val META_SUFFIX = "__"
    @PublishedApi
    internal const val ACCESS_POLICY_UNLOCKED = "unlocked"

    // Metadata `v` field: v1 ciphertext uses a per-entry alias derived from the user key; v2 DEFAULT
    // entries use the datastore master key (locked/unlocked per `u`) while HARDWARE_ISOLATED keeps the
    // per-entry alias; v3 = v2 routing + AUTHENTICATED envelope binding ciphertext to entry identity
    // and security metadata (see [aadFor]). No on-disk migration: entries upgrade when overwritten.
    @PublishedApi
    internal const val ENVELOPE_VERSION_V1 = 1
    @PublishedApi
    internal const val ENVELOPE_VERSION_V2 = 2
    @PublishedApi
    internal const val ENVELOPE_VERSION_V3 = 3
    @PublishedApi
    internal const val ENVELOPE_VERSION_LATEST = ENVELOPE_VERSION_V2

    /**
     * Highest envelope version this build knows the semantics of. The `v` field is plaintext
     * routing metadata (not authenticated), so it can NOT be trusted as a format discriminator
     * beyond what this build defines: an entry recording a HIGHER version was written by a newer
     * KSafe whose alias/AAD semantics are unknown here — decrypting it "as v3" would be a silent
     * misinterpretation. Read paths call [checkKnownEnvelopeVersion] and fail closed instead.
     */
    @PublishedApi
    internal const val ENVELOPE_VERSION_MAX_KNOWN = ENVELOPE_VERSION_V3

    /**
     * Fails closed on an envelope version from the future. The message deliberately avoids every
     * "missing key" phrase the orphan sweep matches on — an unknown-version entry must be
     * PRESERVED (for the newer KSafe that wrote it), never reaped as an orphan.
     *
     * That is why the key is NOT interpolated. Key names come from the calling app and can carry
     * data it did not choose — a per-user key built from a username, for instance — so a name
     * containing a classifier phrase would put that phrase into this message and turn a
     * preserve-me refusal into a delete-me one. The version identifies the entry instead, and
     * that value is one this code produced.
     */
    @PublishedApi
    internal fun checkKnownEnvelopeVersion(version: Int, userKey: String) {
        check(version <= ENVELOPE_VERSION_MAX_KNOWN) {
            "KSafe: an entry records envelope version $version, newer than this KSafe " +
                "understands — refusing to decrypt it as v$ENVELOPE_VERSION_MAX_KNOWN. " +
                "The entry is preserved; upgrade KSafe to read it."
        }
    }

    /**
     * Envelope version for a NEW write at [keyGeneration]: generation 1 stays v2 so an un-rotated
     * store is byte-identical to pre-3.0.0 releases; generation ≥ 2 (post first rotation) writes the
     * authenticated v3 envelope.
     */
    @PublishedApi
    internal fun envelopeVersionForWrite(keyGeneration: Int): Int =
        if (keyGeneration >= 2) ENVELOPE_VERSION_V3 else ENVELOPE_VERSION_V2

    /**
     * Associated data authenticated by a v3 envelope: entry identity (user key) plus every
     * security-relevant metadata field the read path routes on, so tamper that changes where/how the
     * ciphertext decrypts breaks the GCM tag. Layout is canonical and versioned — changing it is a
     * format change.
     */
    @PublishedApi
    /**
     * Store identity for the v3 AAD that survives OS-managed relocation of the user/app
     * home: the [homePath] prefix is replaced with `~`, making the identity home-relative.
     * An iOS app-container UUID changes on every App Store update/restore — an absolute
     * path in the AAD would make every rotated entry fail authentication after the update
     * (and the startup orphan sweep would then delete it). A JVM user home can likewise
     * move (renamed account, OS migration). Distinct logical stores (different
     * directory/fileName) keep distinct identities, preserving the anti-transplant
     * property. Separators are normalized to `/`; paths outside the home stay as passed.
     */
    internal fun stableStoreIdentity(fullPath: String, homePath: String?): String {
        val path = normalizeIdentitySeparators(fullPath)
        val home = homePath?.let(::normalizeIdentitySeparators)?.trimEnd('/')
        if (!home.isNullOrEmpty() && path.startsWith("$home/")) {
            return "~/" + path.removePrefix("$home/")
        }
        // Pass-through, but the "~/" home sigil is escaped so a caller-supplied path that
        // literally begins with it can never collide with a home-relative identity above —
        // the injectivity the anti-transplant AAD binding depends on.
        return if (path.startsWith("~/")) "./$path" else path
    }

    /**
     * Collapse `\` to `/` ONLY on a Windows-shaped path (drive-letter `X:` or UNC `\\`), so the
     * home-prefix match survives mixed separators there. A POSIX path is left untouched:
     * backslash is a legal filename character, and collapsing it would map two distinct files
     * to one identity — defeating the per-store AAD binding.
     */
    private fun normalizeIdentitySeparators(p: String): String =
        if (p.length >= 2 && (p[1] == ':' || (p[0] == '\\' && p[1] == '\\'))) p.replace('\\', '/') else p

    @PublishedApi
    internal fun aadFor(
        storeIdentity: String,
        userKey: String,
        protection: KSafeProtection?,
        requireUnlockedDevice: Boolean,
        keyGeneration: Int,
    ): ByteArray =
        // Length-prefixing the variable-length fields keeps the encoding injective (no delimiter collisions).
        ("ksafe.aad.v3|${storeIdentity.length}:$storeIdentity|${userKey.length}:$userKey|" +
            "${protectionToLiteral(protection)}|${if (requireUnlockedDevice) "u" else "-"}|g$keyGeneration")
            .encodeToByteArray()

    // The sentinels are literal (no regex metacharacters in `[a-z_]`), so they interpolate into a
    // pattern unescaped — which is what lets these guards be built from [KSafeReservedKeys].
    private val MASTERS = "(${KSafeReservedKeys.MASTER}|${KSafeReservedKeys.MASTER_LOCKED})"

    /**
     * Reserved master-key sentinels (± rotation-generation suffix) whose per-entry alias is
     * byte-identical to the store's master alias. Matched EXACT (not prefix) — the rotation sweep's
     * alias math relies on that precision. Write-time reservation lives in [requireWritableUserKey].
     */
    private val RESERVED_USER_KEY = Regex("$MASTERS(${KSafeAliasGrammar.GENERATION_PATTERN})?")

    @PublishedApi
    internal fun isReservedUserKey(key: String): Boolean = RESERVED_USER_KEY.matches(key)

    /**
     * User keys whose trailing dot-segments spell a reserved sentinel whose per-entry engine
     * alias is byte-identical to some internal key slot: a master sentinel (± generation
     * suffix) aliases a store's master (e.g. the default store's key `"vault.__ksafe_master__"`
     * aliases the named store `"vault"`'s master); the strict-variant / rotated-generation
     * sentinels (± fingerprint suffix) alias a sibling key's strict or rotated per-entry alias;
     * and the two JVM vault markers — the deletion tombstone `__ksafe_nsdel__` and the
     * software-fallback mint marker `__ksafe_swfb__`, each appended to a per-entry vault alias —
     * alias a sibling key's marker slot. Writing or deleting such a key could destroy another
     * entry's (or the whole store's) key, or forge/erase a tombstone. (The bare sentinels are
     * already caught by the `__ksafe_` prefix rule.)
     */
    private val RESERVED_ALIAS_SUFFIX_KEY =
        // [\s\S] instead of `.` — the default `.` skips line terminators, so a key containing a
        // newline before the sentinel would slip past this guard and alias a sibling's key.
        // The delimiter class is [.:] because platforms join differently: Android/Apple use a
        // dot, JVM and web join "<fileName>:<userKey>". With only a dot, the DEFAULT store's key
        // "vault:__ksafe_master__" produced exactly the named store "vault"'s master alias and
        // was accepted for writing (and deleting) it.
        Regex(
            """([\s\S]*[.:])?($MASTERS(${KSafeAliasGrammar.GENERATION_PATTERN})?""" +
                "|(${KSafeReservedKeys.STRICT_VARIANT}|${KSafeReservedKeys.ROTATED_VARIANT})" +
                "(${KSafeAliasGrammar.FINGERPRINT_PATTERN})?" +
                """|${KSafeReservedKeys.VAULT_TOMBSTONE}|${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK})"""
        )

    /**
     * A user key that must not be written or deleted through the public API because it aliases
     * KSafe's internal namespaces: `__ksafe_` (on-disk records — a write corrupts store state) or
     * `encrypted_` (the in-memory cache slot for encrypted entries — collides with encrypted entry `X`).
     * Reads are NOT guarded; only mutation is.
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
        // `__ksafe_` is the reserved namespace; `ksafe_key_` is the web engine's legacy localStorage
        // key store. Match only these — a blanket `ksafe_` would swallow user keys starting "ksafe_".
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
            // Fail-closed: absent/unparseable metadata routes through decrypt, never serving
            // ciphertext verbatim (see isCanonicalValueEncrypted).
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
     * Fail-closed encryption decision for a CANONICAL value entry ([VALUE_PREFIX]), which holds
     * plaintext OR ciphertext distinguished only by metadata. Returns true (route through decrypt)
     * UNLESS the metadata is present, parses, and explicitly marks the entry NONE — so tampered,
     * truncated, or half-written metadata fails closed to decrypt rather than handing back raw
     * ciphertext verbatim. A legitimate plaintext write persists `{"v":N,"p":"NONE"}`, so it stays plaintext.
     */
    @PublishedApi
    internal fun isCanonicalValueEncrypted(rawMeta: String?): Boolean {
        if (parseProtection(rawMeta) != null) return true
        // parseProtection returned null: plaintext only if metadata EXPLICITLY says NONE.
        if (rawMeta == null) return true                // absent → fail closed to decrypt
        if (rawMeta == "NONE") return false             // legacy literal, explicitly plaintext
        // Unparseable metadata yields null here → fail closed to decrypt.
        return metaField(parseMetaObject(rawMeta), "p") != "NONE"
    }

    /** Birth timestamp (epoch millis) of the current key generation from the keygen `ts` field; null if absent/unparseable. */
    @PublishedApi
    internal fun parseKeyGenerationTimestamp(raw: String?): Long? =
        metaField(parseMetaObject(raw), "ts")?.toLongOrNull()

    /**
     * Rotation-lifecycle state from the reserved key-generation record:
     * - null: no readable integer `r` (use [hasKeyRotationLifecycle] and
     *   [isLegacy30KeyGenerationState] to distinguish a genuine 3.0.0 record from an unknown
     *   or malformed value);
     * - 0: known completed / already adopted by the resume-aware format;
     * - 1: generation bumped but the pass never reached its durable completion record.
     *
     * Values outside 0/1 are preserved as unknown future/corrupt state; callers must not
     * silently reinterpret them as completed or in-progress.
     */
    internal fun parseKeyRotationLifecycle(raw: String?): Int? =
        metaField(parseMetaObject(raw), "r")?.toIntOrNull()

    /**
     * Whether the lifecycle field itself exists, independently of whether this build
     * understands its value. This distinction is load-bearing for 3.0.0 adoption: only an
     * ABSENT field proves the old format; `r:"future"`, `r:null`, or any other unknown value
     * must be preserved and rejected rather than rewritten as completed.
     */
    internal fun hasKeyRotationLifecycle(raw: String?): Boolean =
        parseMetaObject(raw)?.containsKey("r") == true

    /**
     * Remaining automatic next-instance retries after a normally completed rotation left
     * retryable (`skipped`) entries. `rp:N` is a durable budget, not a timer: the current
     * instance never loops or waits. A claimant changes `r:0,rp:N` atomically to
     * `r:1,rp:N-1` before touching an entry, so a crash cannot restore a consumed attempt.
     *
     * `rp:0` is valid only with `r:1`: it records that the last permitted retry was claimed
     * and may need crash recovery, but completion must not arm another retry. Callers use
     * [hasKeyRotationRetryPending] to distinguish absence from malformed/future state.
     */
    internal fun parseKeyRotationRetryAttempts(raw: String?): Int? =
        metaField(parseMetaObject(raw), "rp")
            ?.toIntOrNull()
            ?.takeIf { it >= 0 }

    /** Whether the pending-retry field exists, even if its value is unsupported. */
    internal fun hasKeyRotationRetryPending(raw: String?): Boolean =
        parseMetaObject(raw)?.containsKey("rp") == true

    /**
     * Whether `rp` is absent or forms a state owned by this release. A completed generation
     * may carry only a positive budget; an in-progress generation may also carry zero because
     * the final attempt is decremented durably before its work begins.
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
     * True only for the exact generation-record shape released by KSafe 3.0.0. A malformed
     * non-null record also has no readable `r`, but must fail closed rather than be mistaken
     * for migration evidence.
     */
    internal fun isLegacy30KeyGenerationState(raw: String?): Boolean {
        val meta = parseMetaObject(raw) ?: return false
        if (meta.keys != setOf("g", "ts")) return false
        val generation = metaField(meta, "g")?.toIntOrNull() ?: return false
        if (generation !in 1..MAX_KEY_GENERATION) return false
        metaField(meta, "ts")?.toLongOrNull() ?: return false
        return true
    }

    /** True only for the one lifecycle value this release owns as an unfinished pass. */
    internal fun parseKeyRotationInProgress(raw: String?): Boolean =
        parseKeyRotationLifecycle(raw) == 1

    /**
     * Builds the resume-aware reserved generation record. The lifecycle field is ALWAYS
     * explicit: `r:0` means completed/adopted, `r:1` means interrupted/in progress. That makes
     * an absent field unambiguously a 3.0.0 record during the 3.1.0 compatibility migration.
     * [timestampMillis] is nullable only for conservative repair of malformed/legacy state;
     * every record KSafe creates normally includes it.
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

    /**
     * Parses the access policy from the metadata JSON `u` field; legacy metadata has none.
     * Takes the [isLegacyProtectionLiteral] fast path because [parseRequireUnlockedDevice] puts
     * this on the read path of every entry.
     */
    @PublishedApi
    internal fun parseAccessPolicy(raw: String?): String? = accessPolicyOf(parseMetaObject(raw))

    /** [parseAccessPolicy] for a caller that already parsed the record; see [parseMetaObject]. */
    internal fun accessPolicyOf(meta: JsonObject?): String? = metaField(meta, "u")

    /** Builds the metadata JSON payload; tests may pass [ENVELOPE_VERSION_V1] to fabricate legacy entries. */
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
            // Generation 1 is the implicit base — omitting `g` keeps the payload byte-identical to pre-rotation releases.
            if (keyGeneration > 1) put("g", keyGeneration)
            // Absent for every pre-variant entry — omitting it keeps legacy payloads byte-identical.
            if (strictAliasVariant) put("sa", 1)
        }
        return payload.toString()
    }

    /**
     * Upper bound on key generations. Generation records are PLAINTEXT routing metadata: a
     * fabricated huge value (tampered backup, corrupted file) would otherwise drive the
     * delete/clearAll per-generation sweep loops for billions of vault round-trips and let the
     * rotation increment wrap negative. 10 000 covers daily rotation for ~27 years;
     * [parseKeyGeneration] clamps anything above it and `rotateKeys` refuses to pass it.
     */
    @PublishedApi
    internal const val MAX_KEY_GENERATION = 10_000

    /**
     * Key generation from raw metadata (which alias generation decrypts the entry). Legacy literals,
     * missing `g`, or anything unparseable is generation 1 — the un-suffixed base alias. Clamped
     * into `1..`[MAX_KEY_GENERATION]; an above-bound value can only come from tamper (nothing
     * writes one) and its entry is unreadable either way, so the clamp changes no honest store.
     */
    @PublishedApi
    internal fun parseKeyGeneration(raw: String?): Int = keyGenerationOf(parseMetaObject(raw))

    /** [parseKeyGeneration] for a caller that already parsed the record; see [parseMetaObject]. */
    internal fun keyGenerationOf(meta: JsonObject?): Int =
        metaField(meta, "g")?.toIntOrNull()?.coerceIn(1, MAX_KEY_GENERATION) ?: 1

    /** Envelope version from raw metadata; anything legacy or unparseable is [ENVELOPE_VERSION_V1]. */
    @PublishedApi
    internal fun parseEnvelopeVersion(raw: String?): Int = envelopeVersionOf(parseMetaObject(raw))

    /** [parseEnvelopeVersion] for a caller that already parsed the record; see [parseMetaObject]. */
    internal fun envelopeVersionOf(meta: JsonObject?): Int =
        metaField(meta, "v")?.toIntOrNull() ?: ENVELOPE_VERSION_V1

    @PublishedApi
    internal fun parseRequireUnlockedDevice(raw: String?): Boolean =
        requireUnlockedDeviceOf(parseMetaObject(raw))

    /** [parseRequireUnlockedDevice] for a caller that already parsed the record; see [parseMetaObject]. */
    internal fun requireUnlockedDeviceOf(meta: JsonObject?): Boolean =
        accessPolicyOf(meta) == ACCESS_POLICY_UNLOCKED

    /**
     * Whether the entry's per-entry key lives under the strict alias variant (3.0.0+ strict
     * `HARDWARE_ISOLATED` writes). Absent/legacy/unparseable metadata is `false` — the entry
     * decrypts under the bare per-entry alias every released version used.
     */
    @PublishedApi
    internal fun parseStrictAliasVariant(raw: String?): Boolean =
        strictAliasVariantOf(parseMetaObject(raw))

    /** [parseStrictAliasVariant] for a caller that already parsed the record; see [parseMetaObject]. */
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
