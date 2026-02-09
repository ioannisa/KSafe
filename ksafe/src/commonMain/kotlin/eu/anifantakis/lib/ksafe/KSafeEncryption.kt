package eu.anifantakis.lib.ksafe

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
 * @see IosKeychainEncryption
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
     * @return The encrypted bytes (typically IV || ciphertext).
     * @throws Exception if encryption fails (key generation error, hardware unavailable, etc.)
     */
    fun encrypt(identifier: String, data: ByteArray): ByteArray

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
}
