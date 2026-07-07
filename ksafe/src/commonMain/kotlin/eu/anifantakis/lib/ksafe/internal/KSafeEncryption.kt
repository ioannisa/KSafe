package eu.anifantakis.lib.ksafe.internal

/**
 * Encryption engine abstraction; lets tests inject a fake engine.
 *
 * Methods are blocking (non-suspend) by design: suspend functions would force
 * `getDirect` through `runBlocking`, risking deadlocks if an implementation switched
 * dispatchers. [encrypt]'s `identifier` is platform-interpreted (Android Keystore
 * alias, iOS Keychain account, JVM key name).
 */
@PublishedApi
internal interface KSafeEncryption {

    /**
     * Encrypts [data] with the key for [identifier] using authenticated encryption
     * (AES-GCM or equivalent), returning IV || ciphertext. [hardwareIsolated]
     * requests StrongBox / Secure Enclave, falling back when unavailable; ignored on
     * JVM/WASM. [requireUnlockedDevice] overrides the engine's key-accessibility
     * policy (`null` = engine default).
     */
    fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null
    ): ByteArray

    /**
     * Decrypts IV || ciphertext produced by [encrypt], authenticating it.
     * [requireUnlockedDevice] = true bypasses engine caches so the hardware policy is
     * actually enforced. Throws on wrong key, tampered data, or missing key.
     */
    fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean? = null): ByteArray

    /** Deletes the key for [identifier]; must be a graceful no-op when the key doesn't exist. */
    fun deleteKey(identifier: String)

    /**
     * Updates the key's accessibility/lock-state policy. Only meaningful on iOS
     * (`SecItemUpdate`); Android re-creates keys instead, JVM has no lock concept.
     */
    fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) { /* no-op by default */ }

    // Suspend variants default to the blocking implementations. The web engine
    // overrides these with async WebCrypto and throws from the blocking ones —
    // browsers have no blocking crypto.

    suspend fun encryptSuspend(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ): ByteArray = encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

    suspend fun decryptSuspend(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean? = null): ByteArray =
        decrypt(identifier, data, requireUnlockedDevice)

    suspend fun deleteKeySuspend(identifier: String) = deleteKey(identifier)

    /**
     * Warms key material so the first real encrypt skips the cold-start key-generation
     * cost. Default: a throwaway encrypt of empty bytes. The Android engine overrides
     * to create only the wrapping KEK — never a DEK — so an unencrypted-only safe
     * writes nothing and prewarm performs no DataStore I/O.
     */
    suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ) {
        encryptSuspend(identifier, ByteArray(0), hardwareIsolated, requireUnlockedDevice)
    }

    /**
     * One-time best-effort eager sweep of legacy key material into the engine's secure
     * store. Lazy per-key migration already guarantees correctness; this shrinks the
     * plaintext exposure window for keys that are never read again. Must be idempotent,
     * non-throwing per entry, and a no-op when there is no safer destination. Default: no-op.
     */
    suspend fun migrateLegacyKeysSuspend() { /* no-op by default */ }

    /**
     * Best-effort read-only warm of an already-persisted DEK into the in-process cache,
     * so the first encrypted read avoids a blocking storage round-trip on the caller's
     * (potentially UI) thread. Unlike [prewarmKey] it reads an existing DEK only —
     * never creates or persists one. Runs on a background scope; a cancelled read is
     * swallowed. Default: no-op (only the Android software-DEK engine has a DEK to warm).
     */
    suspend fun prewarmDekReadIfPresent(
        identifier: String,
        requireUnlockedDevice: Boolean? = null,
    ) { /* no-op by default */ }
}
