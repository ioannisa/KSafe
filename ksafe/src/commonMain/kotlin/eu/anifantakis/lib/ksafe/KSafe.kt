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
 * Secure, type-safe key–value storage for Kotlin Multiplatform. Values are encrypted by
 * default with AES-GCM under a platform-held key (Android Keystore, Apple Keychain, OS
 * secret store on JVM, non-extractable WebCrypto key on Web). [getDirect] reads an
 * in-memory cache; [putDirect] updates it and persists asynchronously.
 */
@Stable
@Suppress("unused")
class KSafe @PublishedApi internal constructor(
    /** Shared orchestrator: hot cache, write coalescer, protection metadata. */
    @PublishedApi internal val core: KSafeCore,

    /** Key storage levels this device supports; what it actually runs at is [protectionInfo]. */
    val deviceKeyStorages: Set<KSafeKeyStorage>,

    /** Builds the per-access [KSafeProtectionInfo]; consumers read [protectionInfo]. */
    @PublishedApi internal val protectionInfoProvider: () -> KSafeProtectionInfo,

    /** Runs after [clearAll] has flushed the core cache. */
    @PublishedApi internal val onClearAllCleanup: suspend () -> Unit = {},
) {
    /** Key custody this instance is currently running with, recomputed on every access. */
    val protectionInfo: KSafeProtectionInfo
        get() = protectionInfoProvider()

    /** Mode used when a write passes none: encrypted with the configured unlock policy. */
    val defaultWriteMode: KSafeWriteMode
        get() = core.defaultEncryptedMode()

    /**
     * Protection tier and key custody of one key, or `null` if it doesn't exist.
     * Blocks once on a cold cache, like [getDirect].
     */
    fun getKeyInfo(key: String): KSafeKeyInfo? = core.getKeyInfo(key)

    /** Deletes a value and its encryption key; the cache updates now, the disk write follows. */
    fun deleteDirect(key: String) = core.deleteDirect(key)

    /** Deletes a value and its encryption key, suspending until the deletion completes. */
    suspend fun delete(key: String) = core.delete(key)

    /**
     * Wipes every preference in this instance and deletes the associated encryption keys.
     * Irreversible. The data wipe throws on failure; key deletion is best-effort and only
     * logged, since the values are already gone.
     */
    suspend fun clearAll() {
        core.clearAll()
        onClearAllCleanup()
    }

    /**
     * Re-encrypts every entry under a fresh key generation and deletes the keys it supersedes;
     * values and the on-disk layout are unchanged. A racing user write wins and its entry lands
     * in [KSafeRotationResult.skipped], still readable under the previous key. Costs a decrypt
     * plus an encrypt per entry. [getOrCreateSecret] secrets keep their value — re-generating
     * one would orphan whatever it encrypts — so only the key wrapping them changes.
     * @throws IllegalStateException if a rotation is already running, or the persisted rotation
     *         state is unknown to this build; the store is left untouched.
     */
    suspend fun rotateKeys(): KSafeRotationResult = core.rotateKeys()

    /**
     * Releases this instance's background coroutines so it can be collected; needed only when
     * re-creating `KSafe` mid-process. Idempotent, and the instance is unusable afterwards.
     */
    fun close() {
        core.cancel()
    }

    // --- NON-BLOCKING API (UI Safe) ---

    /**
     * Non-blocking read from the in-memory cache; safe on the main thread. Blocks once if the
     * cache has not finished its first load.
     * @param T [Boolean], [Int], [Long], [Float], [Double], [String], or a `@Serializable` type.
     * @return the stored value, or [defaultValue] if the key is absent or decryption fails.
     */
    inline fun <reified T> getDirect(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return core.getDirectRaw(key, defaultValue, serializer<T>()) as T
    }

    /**
     * Asynchronous write with an optimistic cache update, using [defaultWriteMode].
     * Fire-and-forget writes have no backpressure: a burst faster than the commit drain holds
     * every pending value in memory, so prefer the suspending [put] for bulk writes.
     */
    inline fun <reified T> putDirect(key: String, value: T) {
        core.putDirectRaw(key, value, core.defaultEncryptedMode(), serializer<T>())
    }

    /** Asynchronous write with an optimistic cache update, using an explicit [mode]. */
    inline fun <reified T> putDirect(key: String, value: T, mode: KSafeWriteMode) {
        core.putDirectRaw(key, value, mode, serializer<T>())
    }

    /**
     * [putDirect] plus [onWriteFailed], invoked once if the background persist fails, after the
     * caches have been rolled back to the durable value; it may run on a background thread.
     * Synchronous failures (unserializable value, reserved key) still throw from this call.
     */
    inline fun <reified T> putDirect(
        key: String,
        value: T,
        mode: KSafeWriteMode,
        noinline onWriteFailed: (Throwable) -> Unit,
    ) {
        core.putDirectRaw(key, value, mode, serializer<T>(), onWriteFailed)
    }

    // --- SUSPEND API (Coroutine Safe) ---

    /**
     * Reads a value, suspending rather than blocking if the cache is not ready. A transient
     * decrypt failure (locked device, busy Keystore/Keychain) is rethrown so the caller can
     * retry after unlock; an absent or corrupt entry returns [defaultValue].
     */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T {
        @Suppress("UNCHECKED_CAST")
        return core.getRaw(key, defaultValue, serializer<T>()) as T
    }

    /**
     * Emits the current value and then every update, distinct-until-changed. On Web only
     * writes made through this same instance are observed.
     */
    inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> {
        @Suppress("UNCHECKED_CAST")
        return core.getFlowRaw(key, defaultValue, serializer<T>()) as Flow<T>
    }

    /** Persists a value, suspending until it is committed, using [defaultWriteMode]. */
    suspend inline fun <reified T> put(key: String, value: T) {
        core.putRaw(key, value, core.defaultEncryptedMode(), serializer<T>())
    }

    /** Persists a value, suspending until it is committed, using an explicit [mode]. */
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
        /** The published version of this artifact, matching its Maven coordinates. */
        val VERSION: String = KSAFE_VERSION
    }
}

/** How KSafe holds values in the in-memory cache. */
enum class KSafeMemoryPolicy {
    /** Discouraged: decrypts every entry at cold start. [LAZY_PLAIN_TEXT] is the cheap equivalent. */
    PLAIN_TEXT,

    /** Values stay as ciphertext in RAM, decrypted on every read; higher CPU per read. */
    ENCRYPTED,

    /** [ENCRYPTED] plus a plaintext side cache with a TTL, so repeated reads skip decryption. */
    ENCRYPTED_WITH_TIMED_CACHE,

    /** Default: decrypts on first read and caches the plaintext; cheap cold start, fast reads. */
    LAZY_PLAIN_TEXT
}

/** Non-inline helper for [getStateFlow]. */
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
 * A hot [StateFlow] of the stored value, shared eagerly in [scope]. The initial value comes
 * from [KSafe.getDirect], so no brief default is emitted first.
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
