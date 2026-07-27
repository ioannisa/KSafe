package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.secureRandomBytes
import eu.anifantakis.lib.ksafe.internal.toLowercaseHex
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Guards concurrent first-time generation to prevent duplicate secrets. */
private val secretMutex = Mutex()

/**
 * Returns (and on first use creates) a cryptographically secure random secret,
 * stored under KSafe's encryption for the logical [key] and isolated per key.
 *
 * Never silently rotated: if a secret exists but can't be read back (backing key
 * invalidated/rotated/wiped, vault temporarily unavailable, or stored value
 * corrupt) this throws rather than mint a new one — overwriting would permanently
 * orphan everything encrypted under the old secret (e.g. a SQLCipher database).
 *
 * @param key Logical name; must be stable for the app's lifetime.
 * @param size Secret length in bytes (default 32 = 256-bit).
 * @param protection Hardware protection level, defaulting to hardware isolation
 *   with platform fallback when unavailable.
 * @param requireUnlockedDevice Whether the device must be unlocked to read it.
 * @throws IllegalArgumentException if [key] is blank or [size] is not positive.
 * @throws IllegalStateException if a secret for [key] exists but cannot be read
 *   back; resolve the vault/key problem and retry, or delete it to rotate.
 */
suspend fun KSafe.getOrCreateSecret(
    key: String = "main_db",
    size: Int = 32,
    protection: KSafeEncryptedProtection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
    requireUnlockedDevice: Boolean = false
): ByteArray {
    require(key.isNotBlank()) { "key must not be blank" }
    require(size > 0) { "size must be positive" }

    // Injective slot: [A-Za-z0-9_] keys use "ksafe_secret_<key>", others hex under "ksafe_secretx_";
    // the '_' vs 'x' prefix split keeps hex and plain slots from ever colliding.
    val safeKey = key.all { it == '_' || it in '0'..'9' || it in 'a'..'z' || it in 'A'..'Z' }
    val storageKey = if (safeKey) "ksafe_secret_$key" else "ksafe_secretx_${hexEncodeUtf8(key)}"
    // Collision-prone legacy slot ('_'-collapsed); the pre-2.2.0 migration source for special-char keys.
    val collapsedKey = key.replace(Regex("[^a-zA-Z0-9_]"), "_")
    val legacyStorageKey = "ksafe_secret_$collapsedKey"
    // Marks "ksafe_secret_<name>" as a live safe-key slot, so a special-char sibling whose collapsed
    // name equals <name> can't misread it (via the legacy probe) as its own secret and silently share it.
    val safeOwnerKey = "ksafe_secretowner_$key"

    return secretMutex.withLock {
        val stored = try {
            get<String>(storageKey, defaultValue = "")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            // Transient decrypt failure with ciphertext present = "exists but unreadable": fall to
            // refuse-to-rotate. Nothing stored = unexpected throw, re-raise.
            if (getKeyInfo(storageKey) == null) throw e
            ""
        }
        when {
            stored.isNotEmpty() -> {
                if (safeKey) markSafeSecretOwner(safeOwnerKey)
                decodeStoredSecret(stored, key, storageKey)
            }

            // Exists but reads back empty ⇒ unreadable; regenerating would orphan old data, so refuse.
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
                // May still exist under the legacy slot — migrate forward before generating. Skip when
                // a safe sibling owns that slot (its collapsed name matches ours): adopting it would
                // hand this key the sibling's live secret and silently share it across two keys.
                val migrated = if (!safeKey && get<String>("ksafe_secretowner_$collapsedKey", "").isEmpty()) {
                    migrateLegacySecret(key, legacyStorageKey, storageKey, protection, requireUnlockedDevice)
                } else null

                migrated ?: run {
                    val secret = secureRandomBytes(size)
                    // Owner marker first: crashing between the two writes then leaves a marker
                    // with an empty slot, which is benign — this branch only runs when no secret
                    // exists, so a sibling's skipped legacy probe finds nothing to lose. The
                    // reverse order leaves a live secret without its marker, which a colliding
                    // special-char sibling would adopt via the legacy probe and silently share.
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

/**
 * Decodes a persisted secret, normalizing a malformed-Base64 failure to the documented
 * "exists but cannot be read back" [IllegalStateException] — the raw [IllegalArgumentException]
 * is reserved by the KDoc contract for caller-input validation (blank key / bad size).
 */
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

/** Lowercase-hex of the UTF-8 bytes of [s] — an injective, [0-9a-f]-only encoding. */
private fun hexEncodeUtf8(s: String): String = s.encodeToByteArray().toLowercaseHex()

/** Idempotently marks a safe key's "ksafe_secret_<name>" slot as safe-owned so a colliding
 *  special-char sibling won't adopt it via the legacy probe. Caller holds [secretMutex]. */
private suspend fun KSafe.markSafeSecretOwner(ownerKey: String) {
    if (get<String>(ownerKey, "").isEmpty()) put(ownerKey, "1", KSafeWriteMode.Plain)
}

/**
 * Migrates a special-char key's secret forward from the legacy slot. Returns the secret, `null`
 * if nothing is stored (caller generates), or throws refuse-to-rotate if a legacy secret exists
 * but is unreadable. Non-destructive: the legacy slot may hold a collision sibling's live secret,
 * so it is never deleted. Caller holds [secretMutex].
 */
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
        // Unreadable → refuse-to-rotate check below; genuinely absent → caller generates.
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
    // Decode BEFORE the copy-forward: a malformed legacy value must throw the documented
    // unreadable-secret failure without being propagated into the canonical slot.
    val secret = decodeStoredSecret(legacyStored, key, legacyStorageKey)
    put(
        key = storageKey,
        value = legacyStored,
        mode = KSafeWriteMode.Encrypted(protection = protection, requireUnlockedDevice = requireUnlockedDevice),
    )
    return secret
}
