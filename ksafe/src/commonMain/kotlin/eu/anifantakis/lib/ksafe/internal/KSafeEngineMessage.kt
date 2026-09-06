package eu.anifantakis.lib.ksafe.internal

/**
 * The message fragments the platform engines throw and the core classifies on. Both ends spell them
 * from here: an engine that phrases a miss differently makes the orphan sweep reap a live entry.
 */
internal object KSafeEngineMessage {
    const val BRAND = "KSafe: "

    const val NO_KEY = "No encryption key found"
    const val KEY_NOT_FOUND = "key not found"
    const val WEB_KEY_MISSING = "web key missing"

    const val WEB_KEY_MISSING_PREFIX = "$BRAND$WEB_KEY_MISSING: "

    /** A temporarily unreachable key store: definitive for reads, retryable for rotation. */
    const val VAULT_UNAVAILABLE = "vault unavailable"
    /** The key exists but the vault is locked or busy — transient, never a miss. */
    const val DEVICE_LOCKED = "device is locked"
    const val KEYSTORE = "Keystore"
    const val KEYCHAIN = "Keychain"

    /** The exact text every engine throws for a definitively absent key; the orphan sweep reclaims on it. */
    fun noKeyFound(identifier: String): String = "$BRAND$NO_KEY for identifier: $identifier"

    private val DEFINITIVE_MISS = listOf(NO_KEY, KEY_NOT_FOUND, WEB_KEY_MISSING).map { BRAND + it }

    /**
     * `contains`, not `startsWith`: Kotlin/Wasm re-wraps JS errors. Anchored on the brand so a
     * caller's key name quoted in another message can't match a miss phrase.
     */
    fun isDefinitiveKeyMiss(message: String?): Boolean {
        val msg = message ?: return false
        return DEFINITIVE_MISS.any { msg.contains(it, ignoreCase = true) }
    }
}
