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
 * Secure, type-safe key–value storage for Kotlin Multiplatform.
 *
 * All data is encrypted by default with AES-256-GCM; key custody is
 * platform-specific (Android Keystore, Apple Keychain, OS secret store on JVM,
 * non-extractable WebCrypto key on Web). Reads ([getDirect]) are served from an
 * in-memory hot cache; writes ([putDirect]) update the cache immediately and
 * persist asynchronously. Use [KSafeWriteMode] per write to opt out of
 * encryption or request hardware isolation.
 *
 * `@Stable` for Compose: instance identity implies equivalent observable
 * behavior, so composables taking a `KSafe` parameter can skip recomposition.
 */
@Stable
@Suppress("unused")
class KSafe @PublishedApi internal constructor(
    /**
     * Shared orchestrator (hot cache, write coalescer, protection metadata).
     * `@PublishedApi internal` so inline reified members and delegate factories
     * can reach it from consumer bytecode without a synthetic accessor.
     */
    @PublishedApi internal val core: KSafeCore,

    /**
     * The key storage levels supported by the current device (never empty);
     * `deviceKeyStorages.max()` is the highest available. A device-capability
     * probe only — for the protection this instance is actually running at
     * (post-fallback), use [protectionInfo].
     */
    val deviceKeyStorages: Set<KSafeKeyStorage>,

    /**
     * Builds the per-access [KSafeProtectionInfo]. The JVM closure recomputes
     * from the engine so a runtime degrade to the software vault shows on the
     * next read; on other platforms it is effectively constant. Consumers
     * should read [protectionInfo] instead.
     */
    @PublishedApi internal val protectionInfoProvider: () -> KSafeProtectionInfo,

    /**
     * Runs after [clearAll] flushes the core cache; JVM uses it to delete the
     * physical DataStore file. Other platforms pass identity.
     */
    @PublishedApi internal val onClearAllCleanup: suspend () -> Unit = {},
) {
    /**
     * The encryption-key custody this instance is currently running with,
     * including any runtime fallback. Recomputed on every access, so a runtime
     * degrade is visible immediately.
     */
    val protectionInfo: KSafeProtectionInfo
        get() = protectionInfoProvider()

    /**
     * Returns the protection tier and actual key custody of a specific key.
     * Prefer [KSafeKeyInfo.level] over the legacy [KSafeKeyInfo.storage].
     * Same cold-start behavior as [getDirect] — blocks once if the cache
     * hasn't initialized.
     *
     * @return The [KSafeKeyInfo] details, or `null` if the key doesn't exist.
     */
    fun getKeyInfo(key: String): KSafeKeyInfo? = core.getKeyInfo(key)

    /**
     * Deletes a value and its associated encryption key asynchronously: the
     * memory cache is updated immediately, the deletion completes in the
     * background.
     */
    fun deleteDirect(key: String) = core.deleteDirect(key)

    /**
     * Deletes a value and its associated encryption key (if any), suspending
     * until the deletion is complete.
     */
    suspend fun delete(key: String) = core.delete(key)

    /**
     * Clears all data in this instance, removing every preference and deleting
     * every associated encryption key. Destructive and irreversible.
     */
    suspend fun clearAll() {
        core.clearAll()
        onClearAllCleanup()
    }

    /**
     * Releases this instance's background infrastructure so it can be
     * garbage-collected. Needed only when re-creating `KSafe` mid-process
     * (tests, hot reload, feature unload) — an abandoned instance is otherwise
     * pinned in heap by its suspended coroutines. Idempotent; the instance can
     * no longer process puts or reads afterwards.
     */
    fun close() {
        core.cancel()
    }

    // --- NON-BLOCKING API (UI Safe) ---

    /**
     * Retrieves a value from the in-memory cache without blocking; safe on the
     * Main/UI thread. Protection is auto-detected from stored metadata. On the
     * very first access, if the cache has not finished initializing, this
     * blocks once; subsequent calls are instant.
     *
     * @param T Supported: [Boolean], [Int], [Long], [Float], [Double],
     *          [String], and `@Serializable` objects.
     * @return The stored value, or [defaultValue] if the key doesn't exist or
     *         decryption fails (see [get] for the suspend-variant contract).
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
     * Retrieves a value, suspending (instead of blocking) if the cache is not
     * ready. Protection is auto-detected from stored metadata.
     *
     * Failure contract: on a *transient* decrypt failure (locked device,
     * momentarily busy Keystore/Keychain) this rethrows so callers can await
     * unlock and retry — unlike [getDirect], which returns [defaultValue], and
     * [getFlow], which skips the emission. A non-transient failure (absent or
     * corrupt ciphertext) still returns [defaultValue].
     */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return core.getRaw(key, defaultValue, serializer<T>()) as T
    }

    /**
     * Returns a [Flow] that emits the current value immediately and then every
     * subsequent update; distinct-until-changed. Protection is auto-detected
     * per emission.
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

    companion object {
        /**
         * The published version of this KSafe artifact (e.g. `"2.1.1"`),
         * guaranteed to match the Maven coordinates of the same build. Also
         * exposed as [KSafeProtectionInfo.kSafeVersion].
         */
        val VERSION: String = KSAFE_VERSION
    }
}

/**
 * Defines how KSafe manages data in the in-memory cache.
 */
enum class KSafeMemoryPolicy {
    /**
     * Discouraged: every encrypted entry is decrypted eagerly at cold start,
     * which can make the first read very slow on large stores.
     * [LAZY_PLAIN_TEXT] gives identical steady-state reads with a cheap cold
     * start; prefer it unless you specifically want decrypt failures surfaced
     * synchronously at startup.
     */
    PLAIN_TEXT,

    /**
     * High security: data stays encrypted (Base64 ciphertext) in RAM and is
     * decrypted on every [getDirect] call. Higher CPU/latency per read; use
     * for sensitive tokens, passwords, or financial data.
     */
    ENCRYPTED,

    /**
     * Like [ENCRYPTED], but recently-decrypted values are kept in a secondary
     * plaintext cache for a TTL (`plaintextCacheTtl` constructor parameter,
     * default 5 seconds), so repeated reads within the window skip decryption.
     * Suited to UI that re-reads the same encrypted property on recomposition.
     */
    ENCRYPTED_WITH_TIMED_CACHE,

    /**
     * Default: entries stay encrypted until first read, which decrypts on
     * demand and caches the plaintext permanently. Cold start is as cheap as
     * [ENCRYPTED] and steady-state reads match [PLAIN_TEXT], at the cost of
     * holding both ciphertext and plaintext for keys that have been read.
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
 * Returns a hot [StateFlow] of the stored value, shared via [stateIn] with
 * [SharingStarted.Eagerly] in [scope]. The initial value is resolved
 * synchronously via [KSafe.getDirect], so an existing value is emitted
 * immediately rather than a brief incorrect default.
 */
inline fun <reified T> KSafe.getStateFlow(
    key: String,
    defaultValue: T,
    scope: CoroutineScope,
): StateFlow<T> = getStateFlowRaw(key, defaultValue, serializer<T>(), scope)

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
