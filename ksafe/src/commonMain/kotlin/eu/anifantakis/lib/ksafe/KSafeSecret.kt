package eu.anifantakis.lib.ksafe

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
        val stored = get<String>(storageKey, defaultValue = "")
        if (stored.isNotEmpty()) {
            Base64.decode(stored)
        } else {
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
