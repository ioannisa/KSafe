package eu.anifantakis.lib.ksafe.internal

/**
 * The character class an `appNamespace` may keep, and the length it is capped at. Shared with the
 * FROZEN legacy spellings ([legacyLossyNamespaceToken], the JVM data-directory token) — those
 * reproduce shipped on-disk identities byte-for-byte, so a widened class or a raised cap in one
 * copy alone would strand a shipped app's data. The three PIPELINES deliberately differ; only
 * these two literals are shared.
 */
internal val NAMESPACE_SANITIZE_REGEX = Regex("[^A-Za-z0-9._-]")
internal const val NAMESPACE_TOKEN_MAX_LENGTH: Int = 120

/**
 * FNV-1a 64-bit parameters, spelled once. KSafe hashes two different domains with them
 * ([namespaceCollisionDigest] over UTF-8 bytes, `KSafeCore.aliasFingerprint` over UTF-16 code
 * units) — the two functions must stay apart, but the constants they share should not be
 * discoverable only under one of two number bases.
 */
internal const val FNV1A_64_OFFSET_BASIS: Long = -0x340d631b7bdddcdbL
internal const val FNV1A_64_PRIME: Long = 0x100000001b3L

/** Width of a 64-bit FNV-1a digest rendered as zero-padded lowercase hex. */
internal const val FNV1A_64_HEX_LENGTH: Int = 16

/**
 * The single canonical `appNamespace` normalization, shared by every consumer of the token
 * (JVM data directory + OS-vault namespace, web data prefix + IndexedDB key prefix).
 *
 * Deliberate equivalences first — whitespace padding and leading dots are cosmetic, so
 * `" foo "`, `".foo"`, and `"foo"` must agree (and stripping leading dots means the token is
 * never `"."`/`".."` → no path traversal). After that the mapping must be injective: invalid
 * characters collapse to `_` and the token is capped at 120 chars, so without a
 * disambiguator two DIFFERENT configured ids (`"a/b"` vs `"a?b"`, or two long ids sharing a
 * 120-char prefix) would silently share data slots and key custody — one store could read,
 * overwrite, or `clearAll()` the other. A lossy token therefore carries a digest of the
 * pre-sanitization id; an already-clean token is unchanged, so documented usage needs no
 * migration.
 */
internal fun canonicalNamespaceToken(raw: String?): String? {
    if (raw == null) return null
    val normalized = raw.trim().trimStart('.')
    val sanitized = NAMESPACE_SANITIZE_REGEX.replace(normalized, "_")
        .take(NAMESPACE_TOKEN_MAX_LENGTH)
        .takeIf { it.isNotEmpty() } ?: return null
    if (sanitized == normalized) return sanitized
    return "$sanitized-${namespaceCollisionDigest(normalized)}"
}

/**
 * 64-bit FNV-1a over the UTF-8 bytes, as 16 lowercase hex chars. Keeps accidentally-colliding
 * sanitized namespaces distinct; not a cryptographic boundary — the namespace is chosen by the
 * app's own developer, so there is no adversarial-collision threat to defend against.
 */
internal fun namespaceCollisionDigest(s: String): String {
    var hash = FNV1A_64_OFFSET_BASIS
    for (byte in s.encodeToByteArray()) {
        hash = hash xor (byte.toLong() and 0xFF)
        hash *= FNV1A_64_PRIME
    }
    return hash.toULong().toString(16).padStart(FNV1A_64_HEX_LENGTH, '0')
}
