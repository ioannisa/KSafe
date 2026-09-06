package eu.anifantakis.lib.ksafe.internal

// FROZEN: shipped installs hold their JVM OS-vault namespace and web/IndexedDB prefixes under this
// exact spelling, and the migration probes only hit if it reproduces them byte-for-byte.
// New callers use canonicalNamespaceToken instead.
internal fun legacyLossyNamespaceToken(raw: String?): String? =
    raw?.trim()?.takeIf { it.isNotEmpty() }
        ?.replace(NAMESPACE_SANITIZE_REGEX, "_")
        ?.take(NAMESPACE_TOKEN_MAX_LENGTH)
        ?.takeIf { it.isNotEmpty() }
