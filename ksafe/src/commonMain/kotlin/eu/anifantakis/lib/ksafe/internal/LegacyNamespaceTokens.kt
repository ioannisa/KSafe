package eu.anifantakis.lib.ksafe.internal

/**
 * The FROZEN pre-canonicalization `appNamespace` normalization: no leading-dot strip and no
 * collision digest, so distinct configured ids could collapse onto one token. Shipped installs hold
 * their JVM OS-vault namespace and their web data / IndexedDB key prefixes under exactly this
 * spelling, and the probes that recover them ([canonicalNamespaceToken]'s migration sources) can
 * only hit if it reproduces those identities byte-for-byte — so it must never change. New callers
 * use [canonicalNamespaceToken].
 */
internal fun legacyLossyNamespaceToken(raw: String?): String? =
    raw?.trim()?.takeIf { it.isNotEmpty() }
        ?.replace(NAMESPACE_SANITIZE_REGEX, "_")
        ?.take(NAMESPACE_TOKEN_MAX_LENGTH)
        ?.takeIf { it.isNotEmpty() }
