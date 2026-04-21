package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer

/**
 * An API for secure key–value storage.
 *
 * KSafe provides a simple, type-safe, and encrypted persistence layer for Kotlin Multiplatform.
 *
 * **Security:**
 * - **Android:** Uses AES-256-GCM with keys stored in the hardware-backed Android Keystore.
 * - **iOS:** Uses AES-256-GCM with symmetric keys stored as Keychain generic-password items (protected by device passcode).
 * - **JVM:** Uses AES-256-GCM with software-backed keys, relying on OS file permissions (0700).
 *
 * **Architecture:**
 * KSafe uses a "Hot Cache" architecture.
 * - Reads (`getDirect`) are instant and non-blocking, serving data from an in-memory atomic cache.
 * - Writes (`putDirect`) are optimistic, updating the memory cache immediately while persisting to disk asynchronously.
 *
 * **The default behavior is to encrypt all data.**
 *
 * **Per-Property Write Mode:**
 * Use [KSafeWriteMode] to control plain/encrypted behavior per property:
 * ```kotlin
 * var counter by ksafe(0) // encrypted (default)
 * var secret by ksafe(
 *     0,
 *     mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)
 * ) // StrongBox / Secure Enclave
 * var setting by ksafe("default", mode = KSafeWriteMode.Plain) // no encryption
 * ```
 *
 * **Biometric Authentication:**
 * For biometric verification, use [verifyBiometric] or [verifyBiometricDirect] independently
 * from storage operations. This gives you full control over when biometrics are required.
 */
@Suppress("unused")
expect class KSafe {
    // --- KEY STORAGE INFO ---

    /**
     * The set of key storage levels supported by the current device.
     *
     * Always contains at least one element. Use `deviceKeyStorages.max()` to get the
     * highest available protection level.
     *
     * | Platform | Possible values |
     * |----------|----------------|
     * | Android  | `{HARDWARE_BACKED}` or `{HARDWARE_BACKED, HARDWARE_ISOLATED}` |
     * | iOS      | `{HARDWARE_BACKED}` or `{HARDWARE_BACKED, HARDWARE_ISOLATED}` |
     * | JVM      | `{SOFTWARE}` |
     * | WASM     | `{SOFTWARE}` |
     */
    val deviceKeyStorages: Set<KSafeKeyStorage>

    /**
     * Returns the protection tier and actual storage location of a specific key.
     *
     * | Scenario | Return value |
     * |----------|-------------|
     * | Key not found | `null` |
     * | Unencrypted key | `KSafeKeyInfo(null, SOFTWARE)` |
     * | Encrypted DEFAULT (Android/iOS) | `KSafeKeyInfo(DEFAULT, HARDWARE_BACKED)` |
     * | Encrypted HARDWARE_ISOLATED (w/ hardware) | `KSafeKeyInfo(HARDWARE_ISOLATED, HARDWARE_ISOLATED)` |
     * | Encrypted HARDWARE_ISOLATED (no hardware) | `KSafeKeyInfo(HARDWARE_ISOLATED, HARDWARE_BACKED)` |
     * | Encrypted (JVM/WASM) | `KSafeKeyInfo(detected_protection, SOFTWARE)` |
     *
     * Same cold-start behavior as [getDirect] — blocks once if cache hasn't initialized.
     *
     * @param key The key name to look up.
     * @return The [KSafeKeyInfo] details, or `null` if the key doesn't exist.
     */
    fun getKeyInfo(key: String): KSafeKeyInfo?


    /**
     * Deletes a value and its associated encryption key asynchronously.
     *
     * This method returns immediately and performs the deletion in the background.
     * The memory cache is updated immediately to reflect the deletion.
     *
     * @param key The key to delete.
     */
    fun deleteDirect(key: String)

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

    // --- INTERNAL RAW API (non-inline, used by thin inline wrappers to reduce bytecode) ---

    /**
     * Non-inline version of [getDirect] that takes an explicit [KSerializer].
     * All heavy logic lives here; the public inline [getDirect] just calls this and casts.
     */
    @PublishedApi internal fun getDirectRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any?

    /**
     * Non-inline version of [putDirect] that takes an explicit [KSerializer].
     */
    @PublishedApi internal fun putDirectRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>)

    /**
     * Non-inline version of [get] (suspend) that takes an explicit [KSerializer].
     */
    @PublishedApi internal suspend fun getRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Any?

    /**
     * Non-inline version of [put] (suspend) that takes an explicit [KSerializer].
     */
    @PublishedApi internal suspend fun putRaw(key: String, value: Any?, mode: KSafeWriteMode, serializer: KSerializer<*>)

    /**
     * Non-inline version of [getFlow] that takes an explicit [KSerializer].
     */
    @PublishedApi internal fun getFlowRaw(key: String, defaultValue: Any?, serializer: KSerializer<*>): Flow<Any?>

    /**
     * Builds the [KSafeWriteMode] used by the no-mode `put`/`putDirect` overloads.
     * Platform-specific because each actual reads `config.requireUnlockedDevice` from
     * its own private constructor parameter.
     */
    @PublishedApi internal fun defaultEncryptedMode(): KSafeWriteMode

    // --- BIOMETRIC API ---

    /**
     * Verifies biometric authentication without accessing storage.
     *
     * Use this when you want to require biometric verification before performing
     * an action. This is completely independent from storage operations.
     *
     * ## Example
     * ```kotlin
     * // Always prompt (no caching)
     * val success = ksafe.verifyBiometric("Authenticate to delete account")
     *
     * // With 60s duration caching (global scope)
     * val success = ksafe.verifyBiometric(
     *     reason = "Authenticate",
     *     authorizationDuration = BiometricAuthorizationDuration(60_000L)
     * )
     *
     * // With 60s duration caching (scoped to settings screen)
     * val success = ksafe.verifyBiometric(
     *     reason = "Authenticate",
     *     authorizationDuration = BiometricAuthorizationDuration(60_000L, "settings-screen")
     * )
     * ```
     *
     * **Platform behavior:**
     * - **iOS:** Triggers Face ID / Touch ID prompt using LocalAuthentication framework.
     * - **Android:** Triggers BiometricPrompt (requires Activity context setup).
     * - **JVM:** Always returns `true` (no biometric hardware).
     *
     * @param reason The reason shown to the user for the biometric prompt.
     * @param authorizationDuration Optional duration configuration for caching successful authentication.
     *        If null (default), authentication is required every time.
     * @return `true` if biometric authentication succeeded, `false` if it failed or was cancelled.
     */
    suspend fun verifyBiometric(
        reason: String = "Authenticate to continue",
        authorizationDuration: BiometricAuthorizationDuration? = null
    ): Boolean

    /**
     * Verifies biometric authentication without accessing storage (non-blocking version).
     *
     * ## Example
     * ```kotlin
     * // Always prompt (no caching)
     * ksafe.verifyBiometricDirect("Authenticate") { success -> }
     *
     * // With 60s duration caching (global scope)
     * ksafe.verifyBiometricDirect(
     *     reason = "Authenticate to save",
     *     authorizationDuration = BiometricAuthorizationDuration(60_000L)
     * ) { success ->
     *     if (success) {
     *         ksafe.putDirect("key", value)
     *     }
     * }
     *
     * // With 60s duration caching (scoped to settings screen)
     * ksafe.verifyBiometricDirect(
     *     reason = "Authenticate to save",
     *     authorizationDuration = BiometricAuthorizationDuration(60_000L, "settings-screen")
     * ) { success -> }
     * ```
     *
     * @param reason The reason shown to the user for the biometric prompt.
     * @param authorizationDuration Optional duration configuration for caching successful authentication.
     *        If null (default), authentication is required every time.
     * @param onResult Callback with `true` if authentication succeeded, `false` otherwise.
     */
    fun verifyBiometricDirect(
        reason: String = "Authenticate to continue",
        authorizationDuration: BiometricAuthorizationDuration? = null,
        onResult: (Boolean) -> Unit
    )

    /**
     * Clears cached biometric authorization for a specific scope or all scopes.
     *
     * Use this to force re-authentication, for example on user logout.
     *
     * @param scope The scope to clear. If null, clears ALL cached authorizations.
     */
    fun clearBiometricAuth(scope: String? = null)
}

// ============================================================================
// Public inline wrappers (reified T) — extension functions so the single copy
// lives in commonMain and every platform inherits it without re-declaring.
// Consumer syntax (`ksafe.getDirect(...)`, `ksafe.put(...)`) is unchanged since
// Kotlin resolves member and extension calls identically at the call site.
// ============================================================================

// --- NON-BLOCKING API (UI Safe) ---

/**
 * Retrieves a value from the in-memory cache immediately.
 *
 * This method is **non-blocking** and safe to call on the Main/UI thread.
 * It reads directly from an atomic memory reference, ensuring zero UI freeze.
 * Protection is auto-detected from stored metadata — no need to specify
 * whether the value was encrypted or not.
 *
 * **Cold Start Behavior:** On the very first app launch, if the cache has not
 * finished initializing, this will block once to ensure data consistency.
 * Subsequent calls are always instant.
 *
 * ## Example
 * ```kotlin
 * val username = ksafe.getDirect("username", "Guest")
 * val token = ksafe.getDirect("auth_token", "")
 * ```
 *
 * @param T The type of value to retrieve. Supported: [Boolean], [Int], [Long],
 *          [Float], [Double], [String], and `@Serializable` objects.
 * @param key The unique key for the value.
 * @param defaultValue The value to return if the key doesn't exist or decryption fails.
 * @return The stored value or [defaultValue].
 */
inline fun <reified T> KSafe.getDirect(key: String, defaultValue: T): T {
    @Suppress("UNCHECKED_CAST")
    return getDirectRaw(key, defaultValue, serializer<T>()) as T
}

/**
 * Updates a value asynchronously with optimistic caching using default encrypted mode.
 *
 * Default encrypted writes use `KSafeConfig.requireUnlockedDevice` as unlock-policy default.
 * Use the overload with explicit [KSafeWriteMode] for plaintext writes or per-entry options.
 */
inline fun <reified T> KSafe.putDirect(key: String, value: T) {
    putDirectRaw(key, value, defaultEncryptedMode(), serializer<T>())
}

/**
 * Updates a value asynchronously with optimistic caching using explicit [KSafeWriteMode].
 *
 * Use this overload for plaintext writes ([KSafeWriteMode.Plain]) or encrypted options
 * such as `requireUnlockedDevice`.
 */
inline fun <reified T> KSafe.putDirect(key: String, value: T, mode: KSafeWriteMode) {
    putDirectRaw(key, value, mode, serializer<T>())
}

// --- SUSPEND API (Coroutine Safe) ---

/**
 * Retrieves a value suspending-ly.
 *
 * Like [getDirect], this checks the memory cache first for performance.
 * If the cache is not ready, it suspends (instead of blocking) until data is loaded.
 * Protection is auto-detected from stored metadata.
 */
suspend inline fun <reified T> KSafe.get(key: String, defaultValue: T): T {
    @Suppress("UNCHECKED_CAST")
    return getRaw(key, defaultValue, serializer<T>()) as T
}

/**
 * Returns a [kotlinx.coroutines.flow.Flow] that emits the value whenever it changes.
 *
 * The Flow emits the current value immediately and then emits any subsequent updates.
 * It is distinct-until-changed. Protection is auto-detected from stored metadata per emission.
 */
inline fun <reified T> KSafe.getFlow(key: String, defaultValue: T): Flow<T> {
    @Suppress("UNCHECKED_CAST")
    return getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
}

/**
 * Persists a value to disk suspending-ly using default encrypted mode.
 */
suspend inline fun <reified T> KSafe.put(key: String, value: T) {
    putRaw(key, value, defaultEncryptedMode(), serializer<T>())
}

/**
 * Persists a value to disk suspending-ly using explicit [KSafeWriteMode].
 */
suspend inline fun <reified T> KSafe.put(key: String, value: T, mode: KSafeWriteMode) {
    putRaw(key, value, mode, serializer<T>())
}

// --- DEPRECATED OVERLOADS (encrypted: Boolean) ---

@Deprecated(
    "Use getDirect(key, defaultValue) instead. Protection is auto-detected on reads.",
    ReplaceWith("getDirect(key, defaultValue)"),
    level = DeprecationLevel.WARNING,
)
inline fun <reified T> KSafe.getDirect(key: String, defaultValue: T, encrypted: Boolean): T =
    getDirect(key, defaultValue)

@Deprecated(
    "Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain",
    ReplaceWith("putDirect(key, value, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)"),
    level = DeprecationLevel.WARNING,
)
inline fun <reified T> KSafe.putDirect(key: String, value: T, encrypted: Boolean) {
    putDirect(key, value, if (encrypted) defaultEncryptedMode() else KSafeWriteMode.Plain)
}

@Deprecated(
    "Use get(key, defaultValue) instead. Protection is auto-detected on reads.",
    ReplaceWith("get(key, defaultValue)"),
    level = DeprecationLevel.WARNING,
)
suspend inline fun <reified T> KSafe.get(key: String, defaultValue: T, encrypted: Boolean): T =
    get(key, defaultValue)

@Deprecated(
    "Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain",
    ReplaceWith("put(key, value, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)"),
    level = DeprecationLevel.WARNING,
)
suspend inline fun <reified T> KSafe.put(key: String, value: T, encrypted: Boolean) {
    put(key, value, if (encrypted) defaultEncryptedMode() else KSafeWriteMode.Plain)
}

@Deprecated(
    "Use getFlow(key, defaultValue) instead. Protection is auto-detected on reads.",
    ReplaceWith("getFlow(key, defaultValue)"),
    level = DeprecationLevel.WARNING,
)
inline fun <reified T> KSafe.getFlow(key: String, defaultValue: T, encrypted: Boolean): Flow<T> =
    getFlow(key, defaultValue)

/**
 * Configuration for biometric authorization duration caching.
 *
 * When provided to [KSafe.verifyBiometric] or [KSafe.verifyBiometricDirect],
 * successful authentication is cached for the specified duration. Subsequent
 * calls within this duration (and same scope) will return `true` without
 * showing a biometric prompt.
 *
 * ## Examples
 * ```kotlin
 * // Cache for 60 seconds (global scope - any call benefits)
 * BiometricAuthorizationDuration(60_000L)
 *
 * // Cache for 60 seconds (scoped to "settings" - only settings calls benefit)
 * BiometricAuthorizationDuration(60_000L, "settings")
 *
 * // Cache for 5 minutes (scoped to user - invalidates on user change)
 * BiometricAuthorizationDuration(300_000L, "user_$userId")
 *
 * // Cache for 60 seconds (screen instance scope - invalidates on navigation)
 * BiometricAuthorizationDuration(60_000L, "screen_${viewModel.hashCode()}")
 * ```
 *
 * @property duration Duration in milliseconds for which the authentication remains valid.
 *           Must be greater than 0.
 * @property scope Optional scope identifier for the authorization session. Different scopes
 *           maintain separate authorization timestamps. Use this to invalidate cached auth
 *           when context changes:
 *           - `null` (default): Global scope, shared across all calls
 *           - Screen ID: Auth valid only while on that screen
 *           - User ID: Auth invalidated on user change
 *           - Random UUID: Forces fresh auth every time (when scope changes)
 */
data class BiometricAuthorizationDuration(
    val duration: Long,
    val scope: String? = null
)


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
    ENCRYPTED,

    /**
     * **Balanced Security & Performance.**
     * Data remains encrypted (Base64 ciphertext) in the primary RAM cache, just like [ENCRYPTED].
     * A secondary plaintext cache stores recently-decrypted values for a configurable TTL.
     *
     * Repeated reads within the TTL window skip decryption entirely (pure memory lookup).
     * After the TTL expires, the plaintext is evicted and the next read decrypts again.
     *
     * **Use case:** Compose/SwiftUI screens that read the same encrypted property multiple
     * times during recomposition/re-render. Only the first read decrypts; subsequent reads
     * within the TTL are instant.
     *
     * Configure the TTL via the `plaintextCacheTtl` constructor parameter (default: 5 seconds).
     */
    ENCRYPTED_WITH_TIMED_CACHE
}

/**
 * Non-inline helper for [getStateFlow]. Avoids duplicating `serializer<T>()` calls.
 */
@PublishedApi
internal fun <T> KSafe.getStateFlowRaw(
    key: String,
    defaultValue: Any?,
    serializer: KSerializer<T>,
    scope: CoroutineScope,
): StateFlow<T> {
    @Suppress("UNCHECKED_CAST")
    val flow = getFlowRaw(key, defaultValue, serializer) as Flow<T>
    @Suppress("UNCHECKED_CAST")
    val initial = getDirectRaw(key, defaultValue, serializer) as T
    return flow.stateIn(scope, SharingStarted.Eagerly, initial)
}

/**
 * Returns a [StateFlow] that holds the current value and emits updates whenever it changes.
 *
 * This is a convenience wrapper around [KSafe.getFlow] that converts the cold [Flow] into
 * a hot [StateFlow] using [stateIn] with [SharingStarted.Eagerly]. The [defaultValue] is
 * used as the fallback for missing keys. The initial [StateFlow] value is resolved
 * synchronously via [KSafe.getDirect], so if a value already exists it is emitted
 * immediately — preventing a brief incorrect emission of the default value.
 * Protection is auto-detected from stored metadata.
 *
 * ## Example
 * ```kotlin
 * val username: StateFlow<String> = ksafe.getStateFlow(
 *     key = "username",
 *     defaultValue = "Guest",
 *     scope = viewModelScope
 * )
 * ```
 *
 * @param T The type of value.
 * @param key The unique key.
 * @param defaultValue The fallback value when no stored value exists.
 * @param scope The [CoroutineScope] used to share the flow (e.g., `viewModelScope`).
 */
inline fun <reified T> KSafe.getStateFlow(
    key: String,
    defaultValue: T,
    scope: CoroutineScope,
): StateFlow<T> = getStateFlowRaw(key, defaultValue, serializer<T>(), scope)

/** @deprecated Remove \"encrypted\" parameter. Protection is now auto-detected during reads.  Your \"encrypted\" param is ignored. */
@Deprecated(
    "Remove \"encrypted\" parameter. Protection is now auto-detected during reads.  Your \"encrypted\" param is ignored. Use getStateFlow(key, defaultValue, scope) instead.",
    ReplaceWith("getStateFlow(key, defaultValue, scope)"),
    level = DeprecationLevel.WARNING
)
inline fun <reified T> KSafe.getStateFlow(
    key: String,
    defaultValue: T,
    scope: CoroutineScope,
    protection: KSafeProtection = KSafeProtection.DEFAULT
): StateFlow<T> = getStateFlowRaw(key, defaultValue, serializer<T>(), scope)

/** @deprecated Use [getStateFlow] without encrypted parameter. */
@Deprecated(
    "Use getStateFlow(key, defaultValue, scope) instead. Protection is auto-detected on reads.",
    ReplaceWith("getStateFlow(key, defaultValue, scope)"),
    level = DeprecationLevel.WARNING
)
inline fun <reified T> KSafe.getStateFlow(
    key: String,
    defaultValue: T,
    scope: CoroutineScope,
    encrypted: Boolean
): StateFlow<T> = getStateFlowRaw(key, defaultValue, serializer<T>(), scope)
