package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.flow.Flow

/**
 * An API for secure key–value storage.
 *
 * KSafe provides a simple, type-safe, and encrypted persistence layer for Kotlin Multiplatform.
 *
 * **Security:**
 * - **Android:** Uses AES-256-GCM with keys stored in the hardware-backed Android Keystore.
 * - **iOS:** Uses AES-256-GCM with keys stored in the Secure Enclave-protected Keychain.
 * - **JVM:** Uses AES-256-GCM with software-backed keys, relying on OS file permissions (0700).
 *
 * **Architecture:**
 * KSafe uses a "Hot Cache" architecture.
 * - Reads (`getDirect`) are instant and non-blocking, serving data from an in-memory atomic cache.
 * - Writes (`putDirect`) are optimistic, updating the memory cache immediately while persisting to disk asynchronously.
 *
 * **The default behavior is to encrypt all data.**
 */
@Suppress("unused")
expect class KSafe {
    // --- NON-BLOCKING API (UI Safe) ---

    /**
     * Retrieves a value from the in-memory cache immediately.
     *
     * This method is **non-blocking** and safe to call on the Main/UI thread.
     * It reads directly from an atomic memory reference, ensuring zero UI freeze.
     *
     * **Cold Start Behavior:** On the very first app launch, if the cache has not
     * finished initializing, this will block once to ensure data consistency.
     * Subsequent calls are always instant.
     *
     * ## Example
     * ```kotlin
     * val username = ksafe.getDirect("username", "Guest")
     * val token = ksafe.getDirect("auth_token", "", encrypted = true)
     * ```
     *
     * @param T The type of value to retrieve. Supported: [Boolean], [Int], [Long],
     *          [Float], [Double], [String], and `@Serializable` objects.
     * @param key The unique key for the value.
     * @param defaultValue The value to return if the key doesn't exist or decryption fails.
     * @param encrypted Whether the value is stored encrypted. Defaults to `true`.
     * @return The stored value or [defaultValue].
     * @see putDirect for the corresponding write operation
     * @see get for the suspending alternative
     */
    inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean = true): T

    /**
     * Updates a value asynchronously with optimistic caching.
     *
     * This method updates the in-memory cache **immediately** (Optimistic Update) and
     * schedules the disk persistence on a background thread.
     *
     * Because the cache update is instant, subsequent calls to [getDirect] will return the new value
     * immediately, even before the disk write completes. This prevents race conditions and UI flicker.
     *
     * @param T The type of value to store.
     * @param key The unique key for the value.
     * @param value The value to store.
     * @param encrypted Whether to encrypt the value before storage. Defaults to `true`.
     */
    inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean = true)

    /**
     * Deletes a value and its associated encryption key asynchronously.
     *
     * This method returns immediately and performs the deletion in the background.
     * The memory cache is updated immediately to reflect the deletion.
     *
     * @param key The key to delete.
     */
    fun deleteDirect(key: String)

    // --- SUSPEND API (Coroutine Safe) ---

    /**
     * Retrieves a value suspending-ly.
     *
     * Like [getDirect], this checks the memory cache first for performance.
     * If the cache is not ready, it suspends (instead of blocking) until data is loaded.
     *
     * @param T The type of value to retrieve.
     * @param key The unique key.
     * @param defaultValue The fallback value.
     * @param encrypted Whether the value is encrypted. Defaults to `true`.
     * @return The stored value.
     */
    suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean = true): T

    /**
     * Returns a [Flow] that emits the value whenever it changes.
     *
     * The Flow emits the current value immediately and then emits any subsequent updates.
     * It is distinct-until-changed, meaning it only emits when the value actually changes.
     *
     * @param T The type of value.
     * @param key The unique key.
     * @param defaultValue The fallback value.
     * @param encrypted Whether the value is encrypted. Defaults to `true`.
     */
    inline fun <reified T> getFlow(key: String, defaultValue: T, encrypted: Boolean = true): Flow<T>

    /**
     * Persists a value to disk suspending-ly.
     *
     * This method suspends until the data has been successfully written to disk.
     * It also updates the memory cache immediately.
     *
     * @param T The type of value.
     * @param key The unique key.
     * @param value The value to store.
     * @param encrypted Whether to encrypt. Defaults to `true`.
     */
    suspend inline fun <reified T> put(key: String, value: T, encrypted: Boolean = true)

    /**
     * Deletes a value and its associated encryption key (if any) from storage.
     *
     * This method suspends until the deletion is complete.
     *
     * @param key The key to delete.
     */
    suspend fun delete(key: String)

    /**
     * Clears **ALL** data in this KSafe instance.
     *
     * This removes all preferences and deletes all associated encryption keys from the Keystore/Keychain.
     * This operation is destructive and cannot be undone.
     */
    suspend fun clearAll()
}


/**
 * Defines how KSafe manages data in the in-memory cache.
 */
enum class KSafeMemoryPolicy {
    /**
     * **High Performance (Default).**
     * Data is decrypted once upon loading and stored as plain text in RAM.
     * Reads are instant ($O(1)$ memory lookup).
     * Use this for UI state, settings, and general data.
     */
    PLAIN_TEXT,

    /**
     * **High Security.**
     * Data remains encrypted (Base64 ciphertext) in RAM.
     * Data is decrypted on-demand every time [getDirect] is called.
     *
     * **Trade-off:** Increases CPU usage and latency per read.
     * Use this for sensitive tokens, passwords, or financial data.
     */
    ENCRYPTED
}