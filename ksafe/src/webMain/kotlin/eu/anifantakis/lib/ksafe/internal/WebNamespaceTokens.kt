package eu.anifantakis.lib.ksafe.internal

// FROZEN: shipped installs hold their data prefix and IndexedDB key records under this token, so
// it must reproduce those identities byte-for-byte. New callers use canonicalNamespaceToken().
internal fun legacyLossyWebNamespaceToken(raw: String?): String? = legacyLossyNamespaceToken(raw)
