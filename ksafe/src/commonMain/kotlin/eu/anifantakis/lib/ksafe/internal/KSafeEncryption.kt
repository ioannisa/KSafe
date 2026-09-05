package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeConfig

/**
 * Encryption engine abstraction; lets tests inject a fake engine. Blocking, not suspend: suspend
 * would force `getDirect` through `runBlocking` and deadlock if an engine switched dispatchers.
 */
@PublishedApi
internal interface KSafeEncryption {

    /**
     * Encrypts [data] with the key for [identifier] (Keystore alias, Keychain account, JVM key
     * name), returning IV || ciphertext. [aad] is authenticated but not encrypted: decryption must
     * present the same bytes. [hardwareIsolated] is a request, ignored on JVM/WASM.
     */
    fun encrypt(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
        aad: ByteArray? = null,
    ): ByteArray

    /**
     * Decrypts IV || ciphertext from [encrypt]; throws on a wrong key, tampered data or [aad], or
     * a missing key. [requireUnlockedDevice] = true bypasses engine caches so the policy is enforced.
     */
    fun decrypt(
        identifier: String,
        data: ByteArray,
        requireUnlockedDevice: Boolean? = null,
        aad: ByteArray? = null,
    ): ByteArray

    /** A graceful no-op when the key doesn't exist. */
    fun deleteKey(identifier: String)

    /** Only meaningful on iOS: Android keys are policy-immutable and JVM has no lock state. */
    fun updateKeyAccessibility(identifier: String, requireUnlocked: Boolean) { /* no-op by default */ }

    /**
     * The whole backing store was wiped. An engine whose key records live inside it (the JVM
     * vault) must drop its key cache, or it encrypts with material that exists only in RAM.
     */
    fun onStoreCleared() { /* no-op by default */ }

    // The web engine overrides these with async WebCrypto and throws from the blocking ones.

    suspend fun encryptSuspend(
        identifier: String,
        data: ByteArray,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
        aad: ByteArray? = null,
    ): ByteArray = encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)

    suspend fun decryptSuspend(
        identifier: String,
        data: ByteArray,
        requireUnlockedDevice: Boolean? = null,
        aad: ByteArray? = null,
    ): ByteArray = decrypt(identifier, data, requireUnlockedDevice, aad)

    suspend fun deleteKeySuspend(identifier: String) = deleteKey(identifier)

    suspend fun prewarmKey(
        identifier: String,
        hardwareIsolated: Boolean = false,
        requireUnlockedDevice: Boolean? = null,
    ) {
        encryptSuspend(identifier, ByteArray(0), hardwareIsolated, requireUnlockedDevice)
    }

    /** Best-effort sweep of legacy key material into the secure store; must be idempotent. */
    suspend fun migrateLegacyKeysSuspend() { /* no-op by default */ }

    /** Warms an already-persisted DEK into the cache; reads only, never creates or persists one. */
    suspend fun prewarmDekReadIfPresent(
        identifier: String,
        requireUnlockedDevice: Boolean? = null,
    ) { /* no-op by default */ }
}

/**
 * The `requireUnlockedDevice` an engine call runs under: an explicit per-write [override] wins.
 * Key attributes and routing both hang off this, so every caller must resolve it identically.
 */
internal fun KSafeConfig.resolveRequireUnlockedDevice(override: Boolean?): Boolean =
    override ?: requireUnlockedDevice
