package eu.anifantakis.lib.ksafe

import androidx.compose.runtime.Stable
import eu.anifantakis.lib.ksafe.internal.KSafeCore
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
 * - **iOS / macOS (native):** Uses AES-256-GCM with symmetric keys stored as Keychain generic-password items (protected by device passcode).
 * - **JVM:** Uses AES-256-GCM with the key protected by the host OS secret store —
 *   Windows DPAPI, macOS Keychain, or Linux Secret Service (libsecret). When no
 *   secret store is available it falls back to a key Base64-encoded in the
 *   DataStore file (legacy behaviour) and logs a one-time warning.
 * - **Web (Kotlin/JS + Kotlin/WASM):** Uses AES-256-GCM via WebCrypto with a
 *   **non-extractable** `CryptoKey` persisted in IndexedDB — the raw key bytes
 *   are never exposed to JS.
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
 * Biometric verification lives in the standalone `:ksafe-biometrics` module
 * (`KSafeBiometrics`) and is fully independent of storage operations. Add the
 * dependency only if you need it.
 */
/**
 * `@Stable` tells the Compose compiler that a `KSafe` instance's behavior is
 * predictable based on instance identity — equal references mean equivalent
 * observable behavior, and the instance does not mutate in ways that would
 * invalidate cached recompositions. This lets composables that accept a
 * `KSafe` parameter (or store one in their environment) skip recomposition
 * when the same instance is passed again. The annotation has BINARY retention
 * and zero runtime cost; non-Compose consumers (Ktor servers, CLI tools)
 * never load it.
 */
@Stable
@Suppress("unused")
class KSafe @PublishedApi internal constructor(
    /**
     * Shared orchestrator. Holds the hot cache, write coalescer, protection
     * metadata, and the non-inline `getXxxRaw`/`putXxxRaw` storage entry points
     * that the public inline reified API and the property delegates forward to.
     *
     * Exposed as `@PublishedApi internal` so inline reified members and inline
     * delegate factories can reach it from consumer bytecode without a
     * synthetic accessor on the hot path.
     */
    @PublishedApi internal val core: KSafeCore,

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
     *
     * This is a *device-capability* probe. For "what protection is this
     * instance actually running at right now (post-fallback)?", use
     * [protectionInfo] instead.
     */
    val deviceKeyStorages: Set<KSafeKeyStorage>,

    /**
     * Live producer of the per-access [KSafeProtectionInfo]. Each platform
     * factory wires a closure that captures the engine and rebuilds the
     * info on demand. Marked `@PublishedApi internal` to keep it off the
     * public surface — consumers should read [protectionInfo] instead.
     *
     * For Android / Apple / Web the closure is effectively a constant
     * (their protection custody can't change after construction). The JVM
     * closure recomputes from `engine.keyVaultIsOsBacked`, so a runtime
     * `degradeToLegacy` (e.g. Compose Desktop release distributable
     * lacking `jdk.unsupported`) is reflected on the very next read.
     */
    @PublishedApi internal val protectionInfoProvider: () -> KSafeProtectionInfo,

    /**
     * Optional callback run after [clearAll] flushes the core cache. JVM uses
     * this to delete the physical DataStore protobuf file (DataStore's own
     * `clear()` leaves an empty file behind). Other platforms pass identity.
     */
    @PublishedApi internal val onClearAllCleanup: suspend () -> Unit = {},
) {
    /**
     * Instance-level diagnostic describing the encryption-key custody this
     * [KSafe] is currently running with — including any runtime fallback
     * (e.g. JVM dropping from `SANDBOX_PROTECTED` to `SOFTWARE` when no
     * OS secret store is reachable, or a Compose Desktop release
     * distributable hitting `LinkageError: sun/misc/Unsafe` and degrading
     * to the software vault mid-process).
     *
     * **Recomputed on every access from 2.1.1** — earlier versions captured
     * this at construction, so a runtime degrade only became visible after
     * a process restart. Now safe to bind to UI / metrics that update.
     *
     * See [KSafeProtectionInfo] for usage patterns.
     */
    val protectionInfo: KSafeProtectionInfo
        get() = protectionInfoProvider()
    /**
     * Returns the protection tier and actual storage location of a specific key.
     *
     * `KSafeKeyInfo` carries both the legacy [KSafeKeyInfo.storage]
     * ([KSafeKeyStorage]) and the new [KSafeKeyInfo.level]
     * ([KSafeProtectionLevel]). Prefer `level` — it's the same scale as
     * [protectionInfo] and additionally distinguishes JVM OS-vault keys
     * (`SANDBOX_PROTECTED`) from the plaintext-in-file fallback (`SOFTWARE`),
     * and Web browser-origin keys (`SANDBOX_PROTECTED`) from raw software
     * (`SOFTWARE`).
     *
     * | Scenario | `protection` | `storage` | `level` |
     * |----------|--------------|-----------|---------|
     * | Key not found | (returns `null`) | | |
     * | Unencrypted key (Plain mode) | `null` | `SOFTWARE` | `SOFTWARE` |
     * | Encrypted DEFAULT (Android / Apple) | `DEFAULT` | `HARDWARE_BACKED` | `HARDWARE_BACKED` |
     * | Encrypted HARDWARE_ISOLATED with StrongBox / SE | `HARDWARE_ISOLATED` | `HARDWARE_ISOLATED` | `HARDWARE_ISOLATED` |
     * | Encrypted HARDWARE_ISOLATED, no hardware (demoted) | `HARDWARE_ISOLATED` | `HARDWARE_BACKED` | `HARDWARE_BACKED` |
     * | Encrypted (JVM, OS vault healthy) | detected | `SOFTWARE` | `SANDBOX_PROTECTED` |
     * | Encrypted (JVM, fallback / opt-out) | detected | `SOFTWARE` | `SOFTWARE` |
     * | Encrypted (Web) | detected | `SOFTWARE` | `SANDBOX_PROTECTED` |
     *
     * Same cold-start behavior as [getDirect] — blocks once if cache hasn't initialized.
     *
     * @param key The key name to look up.
     * @return The [KSafeKeyInfo] details, or `null` if the key doesn't exist.
     */
    fun getKeyInfo(key: String): KSafeKeyInfo? = core.getKeyInfo(key)

    /**
     * Deletes a value and its associated encryption key asynchronously.
     *
     * This method returns immediately and performs the deletion in the background.
     * The memory cache is updated immediately to reflect the deletion.
     *
     * @param key The key to delete.
     */
    fun deleteDirect(key: String) = core.deleteDirect(key)

    /**
     * Deletes a value and its associated encryption key (if any) from storage.
     *
     * This method suspends until the deletion is complete.
     *
     * @param key The key to delete.
     */
    suspend fun delete(key: String) = core.delete(key)

    /**
     * Clears **ALL** data in this KSafe instance.
     *
     * This removes all preferences and deletes all associated encryption keys from the Keystore/Keychain.
     * This operation is destructive and cannot be undone.
     */
    suspend fun clearAll() {
        core.clearAll()
        onClearAllCleanup()
    }

    /**
     * Releases the long-running background infrastructure this instance owns
     * (write consumer, snapshot collector, write channel) so the JVM can
     * garbage-collect it.
     *
     * Optional in production: a `KSafe` that lives for the process lifetime
     * (the typical singleton pattern) doesn't need this — the OS reclaims
     * everything on exit. Call it when you re-create `KSafe` mid-process
     * (test suites, hot-reload during dev, modular feature load/unload),
     * because each abandoned instance is otherwise pinned in heap by its
     * suspended coroutines held as GC roots on `Dispatchers.Default`.
     *
     * Idempotent. After `close()` the instance can no longer process
     * puts or reads.
     */
    fun close() {
        core.cancel()
    }

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
    inline fun <reified T> getDirect(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return core.getDirectRaw(key, defaultValue, serializer<T>()) as T
    }

    /**
     * Updates a value asynchronously with optimistic caching using default encrypted mode.
     *
     * Default encrypted writes use `KSafeConfig.requireUnlockedDevice` as unlock-policy default.
     * Use the overload with explicit [KSafeWriteMode] for plaintext writes or per-entry options.
     */
    inline fun <reified T> putDirect(key: String, value: T) {
        core.putDirectRaw(key, value, core.defaultEncryptedMode(), serializer<T>())
    }

    /**
     * Updates a value asynchronously with optimistic caching using explicit [KSafeWriteMode].
     *
     * Use this overload for plaintext writes ([KSafeWriteMode.Plain]) or encrypted options
     * such as `requireUnlockedDevice`.
     */
    inline fun <reified T> putDirect(key: String, value: T, mode: KSafeWriteMode) {
        core.putDirectRaw(key, value, mode, serializer<T>())
    }

    // --- SUSPEND API (Coroutine Safe) ---

    /**
     * Retrieves a value suspending-ly.
     *
     * Like [getDirect], this checks the memory cache first for performance.
     * If the cache is not ready, it suspends (instead of blocking) until data is loaded.
     * Protection is auto-detected from stored metadata.
     */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return core.getRaw(key, defaultValue, serializer<T>()) as T
    }

    /**
     * Returns a [kotlinx.coroutines.flow.Flow] that emits the value whenever it changes.
     *
     * The Flow emits the current value immediately and then emits any subsequent updates.
     * It is distinct-until-changed. Protection is auto-detected from stored metadata per emission.
     */
    inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> {
        @Suppress("UNCHECKED_CAST")
        return core.getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
    }

    /**
     * Persists a value to disk suspending-ly using default encrypted mode.
     */
    suspend inline fun <reified T> put(key: String, value: T) {
        core.putRaw(key, value, core.defaultEncryptedMode(), serializer<T>())
    }

    /**
     * Persists a value to disk suspending-ly using explicit [KSafeWriteMode].
     */
    suspend inline fun <reified T> put(key: String, value: T, mode: KSafeWriteMode) {
        core.putRaw(key, value, mode, serializer<T>())
    }

    // --- DEPRECATED OVERLOADS (encrypted: Boolean) ---

    @Deprecated(
        "Use getDirect(key, defaultValue) instead. Protection is auto-detected on reads.",
        ReplaceWith("getDirect(key, defaultValue)"),
        level = DeprecationLevel.WARNING,
    )
    inline fun <reified T> getDirect(key: String, defaultValue: T, encrypted: Boolean): T =
        getDirect(key, defaultValue)

    @Deprecated(
        "Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain",
        ReplaceWith("putDirect(key, value, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)"),
        level = DeprecationLevel.WARNING,
    )
    inline fun <reified T> putDirect(key: String, value: T, encrypted: Boolean) {
        putDirect(key, value, if (encrypted) core.defaultEncryptedMode() else KSafeWriteMode.Plain)
    }

    @Deprecated(
        "Use get(key, defaultValue) instead. Protection is auto-detected on reads.",
        ReplaceWith("get(key, defaultValue)"),
        level = DeprecationLevel.WARNING,
    )
    suspend inline fun <reified T> get(key: String, defaultValue: T, encrypted: Boolean): T =
        get(key, defaultValue)

    @Deprecated(
        "Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain",
        ReplaceWith("put(key, value, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)"),
        level = DeprecationLevel.WARNING,
    )
    suspend inline fun <reified T> put(key: String, value: T, encrypted: Boolean) {
        put(key, value, if (encrypted) core.defaultEncryptedMode() else KSafeWriteMode.Plain)
    }

    @Deprecated(
        "Use getFlow(key, defaultValue) instead. Protection is auto-detected on reads.",
        ReplaceWith("getFlow(key, defaultValue)"),
        level = DeprecationLevel.WARNING,
    )
    inline fun <reified T> getFlow(key: String, defaultValue: T, encrypted: Boolean): Flow<T> =
        getFlow(key, defaultValue)
}

/**
 * Defines how KSafe manages data in the in-memory cache.
 */
enum class KSafeMemoryPolicy {
    /**
     * **Discouraged — worst cold-start performance.**
     * Every encrypted entry is decrypted at cold-start load time and stored as plain text in RAM.
     * Reads in steady state are instant ($O(1)$ memory lookup), but cold start pays for every
     * encrypted entry up front: $O(n)$ Keystore round-trips (parallelised in batches of 8 but
     * still serial-IPC bound). On large encrypted stores under poor Keystore conditions this
     * can push first-read latency into ANR territory on Android.
     *
     * **Why this is no longer the default:** [LAZY_PLAIN_TEXT] gives identical steady-state
     * read performance with cheap cold-start — decryption is deferred until each key is
     * actually read, then cached permanently. Apps that touch every key still pay the same
     * total cost; apps that read a subset pay only for what they use.
     *
     * Plaintext also sits in RAM for the full process lifetime (same as [LAZY_PLAIN_TEXT]
     * after first read), so the security profile is unchanged.
     *
     * Prefer [LAZY_PLAIN_TEXT] (the default) unless you have a specific reason to force
     * eager decryption — e.g. you want to surface decrypt failures synchronously at startup
     * rather than at first read.
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
    ENCRYPTED_WITH_TIMED_CACHE,

    /**
     * **Lazy High Performance (Default).**
     * Cold start is cheap — encrypted entries stay as Base64 ciphertext in the primary cache,
     * exactly like [ENCRYPTED]. The first read of each key decrypts on demand and stores the
     * plaintext in a secondary cache permanently. Every subsequent read for that key is an
     * $O(1)$ memory lookup — same performance as [PLAIN_TEXT].
     *
     * **Trade-offs:**
     *  - Cold start: as fast as [ENCRYPTED] (no bulk decryption).
     *  - First read of each key: pays a single decrypt round-trip (~1–3 ms).
     *  - Subsequent reads: as fast as [PLAIN_TEXT].
     *  - Memory: each key, once read, holds both ciphertext and plaintext (~2× the cost of
     *    pure [PLAIN_TEXT] in steady state).
     *
     * Spreads the decryption cost across actual read access instead of paying it up front,
     * so apps that only read a handful of keys never pay for the rest.
     *
     * **Use case:** general-purpose default. Best balance of cold-start latency and
     * steady-state read performance for the common case.
     */
    LAZY_PLAIN_TEXT
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
    val flow = core.getFlowRaw(key, defaultValue, serializer) as Flow<T>
    @Suppress("UNCHECKED_CAST")
    val initial = core.getDirectRaw(key, defaultValue, serializer) as T
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
