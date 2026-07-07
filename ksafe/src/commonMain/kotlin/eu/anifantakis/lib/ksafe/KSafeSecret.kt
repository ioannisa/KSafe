package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.secureRandomBytes
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

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
@OptIn(ExperimentalEncodingApi::class)
suspend fun KSafe.getOrCreateSecret(
    key: String = "main_db",
    size: Int = 32,
    protection: KSafeEncryptedProtection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
    requireUnlockedDevice: Boolean = false
): ByteArray {
    require(key.isNotBlank()) { "key must not be blank" }
    require(size > 0) { "size must be positive" }

    // Injective storage key: a key already in [A-Za-z0-9_] keeps its slot "ksafe_secret_<key>";
    // any other key is hex-encoded under the distinct "ksafe_secretx_" prefix. The prefixes differ
    // at a fixed position ('_' vs 'x'), so a hex slot can never equal a plain slot and distinct
    // keys never collide.
    val safeKey = key.all { it == '_' || it in '0'..'9' || it in 'a'..'z' || it in 'A'..'Z' }
    val storageKey = if (safeKey) "ksafe_secret_$key" else "ksafe_secretx_${hexEncodeUtf8(key)}"
    // Collision-prone legacy slot where non-[A-Za-z0-9_] chars collapse to '_', so distinct
    // special-char keys share it. Equals [storageKey] for a safe key; the migration source otherwise.
    val legacyStorageKey = "ksafe_secret_${key.replace(Regex("[^a-zA-Z0-9_]"), "_")}"

    return secretMutex.withLock {
        val stored = try {
            get<String>(storageKey, defaultValue = "")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            // The suspend get() rethrows a transient decrypt failure (locked device /
            // momentarily-unavailable vault) rather than collapsing it to "". A secret only has
            // ciphertext once it exists, so treat that as "exists but unreadable" and fall to the
            // refuse-to-rotate branch; if nothing is stored the throw is unexpected — re-raise it.
            if (getKeyInfo(storageKey) == null) throw e
            ""
        }
        when {
            stored.isNotEmpty() -> Base64.decode(stored)

            // Entry exists on disk but reads back empty ⇒ unreadable secret. Regenerating
            // would orphan everything encrypted under the old one, so refuse.
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
                // Absent under the injective key. A special-char key may still have a secret under
                // the legacy slot — migrate it forward non-destructively before generating.
                val migrated = if (!safeKey) {
                    migrateLegacySecret(key, legacyStorageKey, storageKey, protection, requireUnlockedDevice)
                } else null

                migrated ?: run {
                    val secret = secureRandomBytes(size)
                    put(
                        key = storageKey,
                        value = Base64.encode(secret),
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

/** Lowercase-hex of the UTF-8 bytes of [s] — an injective, [0-9a-f]-only encoding. */
private fun hexEncodeUtf8(s: String): String {
    val bytes = s.encodeToByteArray()
    val digits = "0123456789abcdef"
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xff
        sb.append(digits[v ushr 4])
        sb.append(digits[v and 0x0f])
    }
    return sb.toString()
}

/**
 * Copies a special-char key's secret forward from the collision-prone legacy slot. Returns the
 * migrated secret, `null` when nothing is stored there (caller generates), or throws the
 * refuse-to-rotate error when a legacy secret exists but can't be read right now. Non-destructive:
 * the legacy slot is never deleted — for a collapsed key it may hold a co-existing distinct key's
 * live secret, so deleting it would orphan the sibling. Caller holds [secretMutex].
 */
@OptIn(ExperimentalEncodingApi::class)
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
        // Legacy slot momentarily unreadable → refuse-to-rotate check below; genuinely absent
        // → let the caller generate.
        if (getKeyInfo(legacyStorageKey) == null) return null
        ""
    }
    if (legacyStored.isEmpty()) {
        if (getKeyInfo(legacyStorageKey) != null) throw IllegalStateException(
            "KSafe.getOrCreateSecret: a pre-2.1.4 secret for key \"$key\" exists under its legacy " +
                "storage slot but could not be read back — the backing key may be invalidated or " +
                "rotated, the OS key vault may be temporarily unavailable, or the value corrupt. " +
                "Refusing to generate a new secret that would orphan it. Resolve the vault/key " +
                "problem and retry, or call delete(\"$legacyStorageKey\") to discard the old secret."
        )
        return null
    }
    put(
        key = storageKey,
        value = legacyStored,
        mode = KSafeWriteMode.Encrypted(protection = protection, requireUnlockedDevice = requireUnlockedDevice),
    )
    return Base64.decode(legacyStored)
}
