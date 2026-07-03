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
 * Returns (and creates on first use) a cryptographically secure random secret.
 *
 * The secret is:
 * - **32 bytes (256-bit) by default** — the recommended length for AES-256.
 * - **Stored using KSafe's hardware-backed encryption**, respecting the requested protection tier.
 * - **Generated once** on first call and retrieved on subsequent calls.
 * - **Tied to a logical key** so each secret is isolated.
 * - **Never silently rotated.** If a secret was created before but can't be
 *   read back now — the backing key was invalidated/rotated/wiped, the key
 *   vault is temporarily unavailable, or the stored value is corrupt — this
 *   throws rather than minting a new secret. Overwriting it would permanently
 *   orphan everything encrypted under the old one (e.g. a SQLCipher database).
 *
 * By default it uses [KSafeEncryptedProtection.HARDWARE_ISOLATED] (StrongBox on Android,
 * Secure Enclave on iOS), falling back to the platform default when hardware isolation
 * is unavailable.
 *
 * ## Database encryption passphrase
 * ```kotlin
 * val passphrase = ksafe.getOrCreateSecret("main.db")
 * val factory = SupportFactory(passphrase)
 * Room.databaseBuilder(context, AppDatabase::class.java, "main.db")
 *     .openHelperFactory(factory)
 *     .build()
 * ```
 *
 * ## API signing key
 * ```kotlin
 * val signingKey = ksafe.getOrCreateSecret("api_signing_key", size = 64)
 * ```
 *
 * ## HMAC key
 * ```kotlin
 * val hmacKey = ksafe.getOrCreateSecret("hmac_auth")
 * ```
 *
 * @param key Logical name for this secret (e.g. database file name, service identifier).
 *            Used to derive the internal storage key. Must be stable for the lifetime of the app.
 * @param size Secret length in bytes (default 32 = 256-bit).
 * @param protection Hardware protection level (defaults to [KSafeEncryptedProtection.HARDWARE_ISOLATED]).
 * @param requireUnlockedDevice Whether the device must be unlocked to read the secret.
 * @return The secret as a [ByteArray].
 * @throws IllegalArgumentException if [key] is blank or [size] is not positive.
 * @throws IllegalStateException if a secret for [key] already exists but cannot
 *   be read back (see "Never silently rotated" above). Resolve the underlying
 *   vault/key problem and retry, or delete the existing secret first to
 *   intentionally rotate it.
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

    val storageKey = "ksafe_secret_${key.replace(Regex("[^a-zA-Z0-9_]"), "_")}"

    return secretMutex.withLock {
        val stored = try {
            get<String>(storageKey, defaultValue = "")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            // Unlike getDirect, the suspend get() path RETHROWS a transient decrypt failure
            // (locked device / momentarily-unavailable vault) instead of collapsing it to ""
            // (FEEDBACK_4 M6). A secret only has ciphertext to decrypt once it exists, so this
            // is the "exists but can't be read right now" case: fall through to the
            // refuse-to-rotate branch below (never regenerate over a still-present secret, and
            // never surface a raw keystore exception). If nothing is stored yet, the read
            // should not have thrown — re-raise the unexpected failure rather than masking it.
            if (getKeyInfo(storageKey) == null) throw e
            ""
        }
        when {
            stored.isNotEmpty() -> Base64.decode(stored)

            // Empty value but the entry EXISTS on disk ⇒ the secret can't be read
            // back (key invalidated/wiped, vault unavailable, or ciphertext
            // corrupt) — `get` collapses all of these to the "" default. Silently
            // regenerating would PERMANENTLY orphan everything encrypted under the
            // old secret (e.g. a SQLCipher database), so refuse instead.
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
                // Genuinely absent (no on-disk entry) — first-time generation.
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
