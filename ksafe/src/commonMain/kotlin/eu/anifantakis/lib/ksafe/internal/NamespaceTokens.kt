package eu.anifantakis.lib.ksafe.internal

/** Character class and length cap an `appNamespace` may keep. Shared with the frozen legacy
 *  spelling, which must reproduce shipped on-disk identities — widening either strands data. */
internal val NAMESPACE_SANITIZE_REGEX = Regex("[^A-Za-z0-9._-]")
internal const val NAMESPACE_TOKEN_MAX_LENGTH: Int = 120

/** FNV-1a 64-bit parameters, shared by [namespaceCollisionDigest] (UTF-8 bytes) and
 *  `KSafeCore.aliasFingerprint` (UTF-16 code units); both spell on-disk identities, so neither
 *  may adopt the other's input encoding. */
internal const val FNV1A_64_OFFSET_BASIS: Long = -0x340d631b7bdddcdbL
internal const val FNV1A_64_PRIME: Long = 0x100000001b3L

internal const val FNV1A_64_HEX_LENGTH: Int = 16

/**
 * The one canonical `appNamespace` normalization. Leading dots are stripped so the token is never
 * `.`/`..`; a lossy sanitize or cap gets a digest suffix, or two ids could share data and keys.
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

/** 64-bit FNV-1a over the UTF-8 bytes, as 16 lowercase hex chars. Keeps colliding sanitized
 *  namespaces distinct; not a cryptographic boundary. */
internal fun namespaceCollisionDigest(s: String): String {
    var hash = FNV1A_64_OFFSET_BASIS
    for (byte in s.encodeToByteArray()) {
        hash = hash xor (byte.toLong() and 0xFF)
        hash *= FNV1A_64_PRIME
    }
    return hash.toULong().toString(16).padStart(FNV1A_64_HEX_LENGTH, '0')
}
