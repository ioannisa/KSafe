package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeSecretSlots
import eu.anifantakis.lib.ksafe.internal.secureRandomBytes
import eu.anifantakis.lib.ksafe.internal.toLowercaseHex
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Serializes first-time generation so two callers can't mint different secrets for one key. */
private val secretMutex = Mutex()

/**
 * Returns (and on first use creates) a cryptographically secure random secret of [size] bytes for
 * [key], stored encrypted in a reserved `ksafe_secret…` slot. Use it for a value the app must
 * reproduce exactly later, such as a SQLCipher passphrase. Concurrent calls are serialized, so two
 * first calls for one [key] yield the same secret.
 *
 * Never silently rotated: if a secret exists but cannot be read back this throws instead of minting
 * a new one, which would orphan everything encrypted under it. [KSafe.rotateKeys] keeps the value.
 *
 * @param key Logical name; must be stable for the app's lifetime.
 * @param size Length in bytes; 32 = 256-bit.
 * @param protection Storage tier; [KSafeEncryptedProtection.HARDWARE_ISOLATED] degrades to the
 *   platform default where no security chip exists.
 * @param requireUnlockedDevice Readable only while the device is unlocked; enforced on Android and Apple only.
 * @throws IllegalArgumentException if [key] is blank or [size] is not positive.
 * @throws IllegalStateException if a secret for [key] exists but cannot be read back; fix the vault
 *   or key problem and retry, or `delete` the slot named in the message to discard it.
 */
suspend fun KSafe.getOrCreateSecret(
    key: String = "main_db",
    size: Int = 32,
    protection: KSafeEncryptedProtection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
    requireUnlockedDevice: Boolean = false
): ByteArray {
    require(key.isNotBlank()) { "key must not be blank" }
    require(size > 0) { "size must be positive" }

    // Injective slot: the '_' vs 'x' prefix split keeps hex and plain slots from ever colliding.
    val safeKey = key.all { it == '_' || it in '0'..'9' || it in 'a'..'z' || it in 'A'..'Z' }
    val storageKey = if (safeKey) {
        KSafeSecretSlots.PLAIN_PREFIX + key
    } else {
        KSafeSecretSlots.HEX_PREFIX + hexEncodeUtf8(key)
    }
    val collapsedKey = key.replace(Regex("[^a-zA-Z0-9_]"), "_")
    val legacyStorageKey = KSafeSecretSlots.PLAIN_PREFIX + collapsedKey
    // Marks the plain slot as safe-owned, so a colliding special-char sibling can't adopt its secret.
    val safeOwnerKey = "ksafe_secretowner_$key"

    return secretMutex.withLock {
        val stored = try {
            get<String>(storageKey, defaultValue = "")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            // Ciphertext present = "exists but unreadable" → refuse-to-rotate below; nothing stored → rethrow.
            if (getKeyInfo(storageKey) == null) throw e
            ""
        }
        when {
            stored.isNotEmpty() -> {
                if (safeKey) markSafeSecretOwner(safeOwnerKey)
                decodeStoredSecret(stored, key, storageKey)
            }

            getKeyInfo(storageKey) != null -> throw IllegalStateException(
                "KSafe.getOrCreateSecret: a secret for key \"$key\" exists but could not be " +
                    "read back — the backing encryption key may have been invalidated or " +
                    "rotated, the OS key vault may be temporarily unavailable, or the stored " +
                    "value may be corrupt. Refusing to overwrite it: generating a new secret " +
                    "would permanently orphan any data encrypted under the existing one (e.g. " +
                    "a SQLCipher database). Resolve the vault/key problem and retry, or call " +
                    "delete(\"$storageKey\") first to intentionally discard the old secret."
            )

            else -> {
                // Skip the legacy probe when a safe sibling owns that slot: adopting it would hand
                // this key the sibling's live secret.
                val migrated = if (!safeKey && get<String>("ksafe_secretowner_$collapsedKey", "").isEmpty()) {
                    migrateLegacySecret(key, legacyStorageKey, storageKey, protection, requireUnlockedDevice)
                } else null

                migrated ?: run {
                    val secret = secureRandomBytes(size)
                    // Marker before the secret: the reverse order leaves a live secret unmarked,
                    // which a colliding special-char sibling would adopt and share.
                    if (safeKey) markSafeSecretOwner(safeOwnerKey)
                    put(
                        key = storageKey,
                        value = KSafeBase64.encode(secret),
                        mode = KSafeWriteMode.Encrypted(
                            protection = protection,
                            requireUnlockedDevice = requireUnlockedDevice
                        )
                    )
                    secret
                }
            }
        }
    }
}

/** Decodes a persisted secret, mapping malformed Base64 to the documented [IllegalStateException]. */
private fun decodeStoredSecret(stored: String, key: String, slot: String): ByteArray = try {
    KSafeBase64.decode(stored)
} catch (e: IllegalArgumentException) {
    throw IllegalStateException(
        "KSafe.getOrCreateSecret: a secret for key \"$key\" exists but is not valid Base64 — " +
            "the reserved slot \"$slot\" was likely overwritten outside getOrCreateSecret, or " +
            "the stored value is corrupt. Refusing to overwrite it: generating a new secret " +
            "would permanently orphan any data encrypted under the existing one. Restore the " +
            "value, or call delete(\"$slot\") to intentionally discard it.",
        e,
    )
}

private fun hexEncodeUtf8(s: String): String = s.encodeToByteArray().toLowercaseHex()

/** Marks a safe key's slot as safe-owned so a colliding sibling won't adopt it. Caller holds [secretMutex]. */
private suspend fun KSafe.markSafeSecretOwner(ownerKey: String) {
    if (get<String>(ownerKey, "").isEmpty()) put(ownerKey, "1", KSafeWriteMode.Plain)
}

/** Migrates a special-char key's secret forward from the legacy slot; null when nothing is stored.
 *  Non-destructive: the legacy slot may hold a sibling's live secret. Caller holds [secretMutex]. */
private suspend fun KSafe.migrateLegacySecret(
    key: String,
    legacyStorageKey: String,
    storageKey: String,
    protection: KSafeEncryptedProtection,
    requireUnlockedDevice: Boolean,
): ByteArray? {
    val legacyStored = try {
        get<String>(legacyStorageKey, defaultValue = "")
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        if (getKeyInfo(legacyStorageKey) == null) return null
        ""
    }
    if (legacyStored.isEmpty()) {
        if (getKeyInfo(legacyStorageKey) != null) throw IllegalStateException(
            "KSafe.getOrCreateSecret: a pre-2.2.0 secret for key \"$key\" exists under its legacy " +
                "storage slot but could not be read back — the backing key may be invalidated or " +
                "rotated, the OS key vault may be temporarily unavailable, or the value corrupt. " +
                "Refusing to generate a new secret that would orphan it. Resolve the vault/key " +
                "problem and retry, or call delete(\"$legacyStorageKey\") to discard the old secret."
        )
        return null
    }
    // Decode before the copy-forward, or a malformed value propagates into the canonical slot.
    val secret = decodeStoredSecret(legacyStored, key, legacyStorageKey)
    put(
        key = storageKey,
        value = legacyStored,
        mode = KSafeWriteMode.Encrypted(protection = protection, requireUnlockedDevice = requireUnlockedDevice),
    )
    return secret
}
