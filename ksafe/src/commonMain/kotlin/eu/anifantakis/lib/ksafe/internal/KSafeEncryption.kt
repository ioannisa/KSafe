package eu.anifantakis.lib.ksafe.internal

/**
 * Internal interface for encryption engines.
 *
 * This abstraction allows:
 * 1. **Testability:** Inject a [FakeEncryption] in unit tests to verify KSafe logic without
 *    requiring platform-specific keystores or emulators.
 * 2. **Future Extensibility:** If enterprise customers require custom encryption (e.g., FIPS-compliant
 *    libraries, Google Tink), this interface can be made public with appropriate annotations.
 *
 * ## Design Decisions
 *
 * - **Blocking (non-suspend) methods:** Encryption is CPU-bound work. Using suspend functions
 *   would force `getDirect` to call `runBlocking`, risking deadlocks if the implementation
 *   switches dispatchers. KSafe handles threading internally.
 *
 * - **`identifier` parameter:** A generic string that each platform implementation interprets
 *   as needed (Android Keystore alias, iOS Keychain account, JVM key name, etc.).
 *
 * - **`deleteKey` method:** Required for proper cleanup when preferences are deleted.
 *   The encryption key must be removed alongside the encrypted data.
 *
 * @see AndroidKeystoreEncryption
 * @see AppleKeychainEncryption
 * @see JvmSoftwareEncryption
 */
@PublishedApi
internal interface KSafeEncryption {

    /**
     * Encrypts plaintext data.
     *
     * The implementation is responsible for:
     * - Generating or retrieving the cryptographic key associated with [identifier]
     * - Generating a random IV/nonce
     * - Encrypting the data using AES-GCM (or equivalent authenticated encryption)
     * - Returning the IV prepended to the ciphertext (IV || ciphertext)
     *
     * @param identifier Unique identifier for the encryption key. Platform-specific interpretation:
     *                   - Android: Keystore alias
     *                   - iOS: Keychain account name
     *                   - JVM: Key identifier in storage
     * @param data The plaintext bytes to encrypt.
     * @param hardwareIsolated When true, attempt to use hardware-isolated key storage
     *   (StrongBox on Android, Secure Enclave on iOS). Falls back to default storage
     *   if hardware isolation is unavailable. Ignored on JVM/WASM.
     * @param requireUnlockedDevice Optional per-call override for key accessibility policy.
     *   `null` means use engine default/configuration.
     * @return The encrypted bytes (typically IV || ciphertext).
     * @throws Exception if encryption fails (key generation error, hardware unavailable, etc.)
     */
    fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null
    ): ByteArray

    /**
     * Decrypts ciphertext data.
     *
     * The implementation is responsible for:
     * - Retrieving the cryptographic key associated with [identifier]
     * - Extracting the IV from the input (typically first 12 bytes for GCM)
     * - Decrypting and authenticating the data
     *
     * @param identifier Unique identifier for the encryption key.
     * @param data The encrypted bytes (typically IV || ciphertext).
     * @return The decrypted plaintext bytes.
     * @throws Exception if decryption fails (wrong key, tampered data, missing key, etc.)
     */
    fun decrypt(identifier: String, data: ByteArray): ByteArray

    /**
     * Deletes the cryptographic key associated with the identifier.
     *
     * This should be called when a preference is deleted to ensure the encryption key
     * is also removed from the secure storage (Keystore/Keychain).
     *
     * Implementations should handle the case where the key doesn't exist gracefully
     * (no-op, no exception).
     *
     * @param identifier Unique identifier for the key to delete.
     */
    fun deleteKey(identifier: String)

    /**
     * Updates the accessibility/lock-state policy for an existing key.
     *
     * Only meaningful on iOS where Keychain items have an accessibility attribute
     * that can be changed via `SecItemUpdate`. Android re-creates keys instead,
     * and JVM has no lock concept.
     *
     * @param identifier Unique identifier for the key to update.
     * @param requireUnlocked If true, restrict access to when the device is unlocked.
     */
    fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) { /* no-op by default */ }

    // ------------------------------------------------------------------------
    // Suspend variants. Default impls delegate to the blocking ones so every
    // existing engine (Android/iOS/JVM) works unchanged. The web engine
    // overrides these with real async WebCrypto work and throws from the
    // blocking counterparts — browsers have no blocking crypto.
    //
    // KSafeCore calls the suspend variants from every code path that is
    // already inside a coroutine (write coalescer, orphan cleanup, background
    // preload, suspend `put`). The one remaining blocking call site is
    // `resolveFromCache` invoked via `getDirect`; web avoids it by running
    // exclusively in PLAIN_TEXT memory-policy mode, where decryption happens
    // at bootstrap time and the cache already holds plaintext.
    // ------------------------------------------------------------------------

    suspend fun encryptSuspend(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ): ByteArray = encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

    suspend fun decryptSuspend(identifier: String, data: ByteArray): ByteArray =
        decrypt(identifier, data)

    suspend fun deleteKeySuspend(identifier: String) = deleteKey(identifier)

    /**
     * Warms the key material for [identifier] so the first real encrypt doesn't pay the
     * cold-start key-generation cost. Default: a throwaway encrypt of empty bytes — exactly
     * what [KSafeCore]'s prewarm used to do, which on Keychain/OS-vault engines primes the
     * in-memory key cache.
     *
     * Engines may override to warm **only** what's needed and avoid side effects. The Android
     * engine overrides this to create just the wrapping KEK: it deliberately does **not**
     * generate or persist a DEK at prewarm, so an unencrypted-only safe never writes one and
     * prewarm performs no DataStore I/O (the DEK is created lazily on the first real encrypt).
     */
    suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ) {
        encryptSuspend(identifier, ByteArray(0), hardwareIsolated, requireUnlockedDevice)
    }

    /**
     * One-time, best-effort **eager** sweep of legacy (pre-2.1) key material
     * out of the weak storage location into the engine's secure store.
     *
     * Lazy per-key migration ([getOrCreateSecretKey]-style, on first
     * read/write) already guarantees correctness, but a key that is never
     * read again would keep its plaintext sitting in the compromisable
     * location indefinitely. `KSafeCore` calls this once from the
     * first-snapshot background pass (off the construction/UI path) so the
     * exposure window for cold keys shrinks to a single post-upgrade session.
     *
     * Must be: idempotent, non-throwing for individual entries, and a no-op
     * when there is no safer destination (JVM software-fallback / opt-out).
     * Default: no-op (Android/Apple have no weak legacy key location).
     */
    suspend fun migrateLegacyKeysSuspend() { /* no-op by default */ }
}
