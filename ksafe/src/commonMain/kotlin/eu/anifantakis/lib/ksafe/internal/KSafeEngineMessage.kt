package eu.anifantakis.lib.ksafe.internal

/**
 * The message fragments the platform engines throw and the core classifies on. A stringly-typed
 * protocol: an engine that phrases a miss differently makes the orphan sweep either skip a real
 * orphan or reap a live entry, so both ends spell the phrase from here.
 */
internal object KSafeEngineMessage {
    /** A definitively absent key — the phrase the orphan sweep reclaims ciphertext on. */
    const val NO_KEY = "No encryption key found"
    const val KEY_NOT_FOUND = "key not found"
    const val WEB_KEY_MISSING = "web key missing"
    /** A temporarily unreachable key store: definitive for reads, retryable for rotation. */
    const val VAULT_UNAVAILABLE = "vault unavailable"
    /** Transient: the key exists but the platform vault is locked or busy. */
    const val DEVICE_LOCKED = "device is locked"
    const val KEYSTORE = "Keystore"
    const val KEYCHAIN = "Keychain"

    /**
     * The whole canonical missing-key message, not just its phrase: every engine throws this exact
     * text for a definitively absent key, and the orphan sweep reclaims ciphertext on it.
     */
    fun noKeyFound(identifier: String): String = "KSafe: $NO_KEY for identifier: $identifier"
}
