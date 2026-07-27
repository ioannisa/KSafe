package eu.anifantakis.lib.ksafe.internal

/**
 * The FROZEN ≤ 2.2.1 web `appNamespace` normalization (no leading-dot strip, no collision
 * digest — distinct configured ids could collapse to one token). Shipped installs hold their
 * data prefix and IndexedDB key records under this token, so it must reproduce old on-disk
 * identities byte-for-byte and never change — new callers use [canonicalNamespaceToken].
 */
internal fun legacyLossyWebNamespaceToken(raw: String?): String? = legacyLossyNamespaceToken(raw)
