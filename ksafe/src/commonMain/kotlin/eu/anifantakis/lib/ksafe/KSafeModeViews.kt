package eu.anifantakis.lib.ksafe

import androidx.compose.runtime.Stable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.properties.ReadOnlyProperty
import kotlin.properties.ReadWriteProperty

/**
 * A write-mode view over an existing [KSafe]: every write made through this handle is
 * [KSafeWriteMode.Plain]. There is no `mode` parameter anywhere on this type, so a call
 * site can never accidentally encrypt a preference or store a secret in plaintext by
 * picking the wrong argument — the type IS the decision.
 *
 * Views share the underlying store. Three views over one instance read and write the same
 * file, the same key namespace and the same cache — a value written through [KSafePlain]
 * is immediately visible through the raw [KSafe] or any other view. This is the intended
 * pattern for dependency injection:
 *
 * ```kotlin
 * single { KSafe(context = androidApplication(), fileName = "app") }
 * single { KSafePlain(get()) }
 * single { KSafeHardwareIsolated(get()) }
 *
 * class SettingsRepository(private val prefs: KSafePlain)        // writes are always Plain
 * class AuthRepository(private val vault: KSafeHardwareIsolated) // writes always request SE/StrongBox
 * ```
 *
 * The guarantee is **write-side only**: reads carry no mode — KSafe auto-detects each
 * stored entry's protection — so `KSafePlain.get()` happily reads a value that some other
 * handle wrote encrypted. Think "writes through this handle are plain", never "values from
 * this handle are plain".
 *
 * Store-scoped operations ([KSafe.rotateKeys], [KSafe.clearAll], [KSafe.close],
 * [KSafe.protectionInfo], [KSafe.getKeyInfo], `awaitCacheReady`, `getOrCreateSecret`) are
 * deliberately absent: they concern the whole store, not a mode view. Call them on [ksafe],
 * the underlying instance this view exposes.
 */
@Stable
class KSafePlain(val ksafe: KSafe) {

    /** The frozen write mode — always [KSafeWriteMode.Plain]. */
    val mode: KSafeWriteMode get() = KSafeWriteMode.Plain

    /** Suspend write; always [KSafeWriteMode.Plain]. See [KSafe.put]. */
    suspend inline fun <reified T> put(key: String, value: T) =
        ksafe.put(key, value, KSafeWriteMode.Plain)

    /** Fire-and-forget write; always [KSafeWriteMode.Plain]. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T) =
        ksafe.putDirect(key, value, KSafeWriteMode.Plain)

    /** Fire-and-forget write with a failure callback. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T, noinline onWriteFailed: (Throwable) -> Unit) =
        ksafe.putDirect(key, value, KSafeWriteMode.Plain, onWriteFailed)

    /** Suspend read. Reads are mode-free — protection is auto-detected. See [KSafe.get]. */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T =
        ksafe.get(key, defaultValue)

    /** Cache read. Reads are mode-free — protection is auto-detected. See [KSafe.getDirect]. */
    inline fun <reified T> getDirect(key: String, defaultValue: T): T =
        ksafe.getDirect(key, defaultValue)

    /** Cold observable read. See [KSafe.getFlow]. */
    inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> =
        ksafe.getFlow(key, defaultValue)

    /** Hot observable read. See [KSafe.getStateFlow]. */
    inline fun <reified T> getStateFlow(key: String, defaultValue: T, scope: CoroutineScope): StateFlow<T> =
        ksafe.getStateFlow(key, defaultValue, scope)

    /** Removes the value and its key material. See [KSafe.delete]. */
    suspend fun delete(key: String) = ksafe.delete(key)

    /** Fire-and-forget removal. See [KSafe.deleteDirect]. */
    fun deleteDirect(key: String) = ksafe.deleteDirect(key)

    /**
     * Property delegate; writes are always [KSafeWriteMode.Plain]. With no [key] the
     * storage key is the property's own name, exactly as with `by ksafe(...)`.
     */
    inline operator fun <reified T> invoke(
        defaultValue: T,
        key: String? = null,
    ): ReadWriteProperty<Any?, T> = ksafe.invoke(defaultValue, key, KSafeWriteMode.Plain)

    /** Read-only cold-Flow delegate. See [KSafe.asFlow]. */
    inline fun <reified T> asFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, Flow<T>> = ksafe.asFlow(defaultValue, key)

    /** Writable cold-Flow delegate; `set` writes are always Plain. See [KSafe.asWritableFlow]. */
    inline fun <reified T> asWritableFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
        ksafe.asWritableFlow(defaultValue, key, KSafeWriteMode.Plain)

    /** Read-only StateFlow delegate. See [KSafe.asStateFlow]. */
    inline fun <reified T> asStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, StateFlow<T>> = ksafe.asStateFlow(defaultValue, scope, key)

    /** MutableStateFlow delegate; writes are always Plain. See [KSafe.asMutableStateFlow]. */
    inline fun <reified T> asMutableStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
        ksafe.asMutableStateFlow(defaultValue, scope, key, KSafeWriteMode.Plain)
}

/**
 * A write-mode view over an existing [KSafe]: every write made through this handle is
 * [KSafeWriteMode.Encrypted] at the [KSafeEncryptedProtection.DEFAULT] tier, with the
 * unlock policy frozen at construction. No `mode` parameter exists anywhere on this type.
 *
 * [requireUnlockedDevice] defaults to the underlying instance's configured policy
 * ([KSafeConfig.requireUnlockedDevice], surfaced as [KSafe.defaultWriteMode]) so that
 * `KSafeEncrypted(ksafe).put(k, v)` behaves exactly like a modeless `ksafe.put(k, v)`.
 * Pass it explicitly to pin a stricter (or looser) policy for everything written through
 * this view.
 *
 * The guarantee is **write-side only** — reads are mode-free and auto-detect each entry's
 * protection. Store-scoped operations live on [ksafe]; see [KSafePlain] for the shared
 * view semantics and the DI pattern.
 */
@Stable
class KSafeEncrypted(
    val ksafe: KSafe,
    requireUnlockedDevice: Boolean =
        (ksafe.defaultWriteMode as? KSafeWriteMode.Encrypted)?.requireUnlockedDevice ?: false,
) {

    /** The frozen write mode — `Encrypted(DEFAULT, requireUnlockedDevice)`. */
    val mode: KSafeWriteMode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.DEFAULT,
        requireUnlockedDevice = requireUnlockedDevice,
    )

    /** Suspend write; always encrypted with this view's frozen [mode]. See [KSafe.put]. */
    suspend inline fun <reified T> put(key: String, value: T) = ksafe.put(key, value, mode)

    /** Fire-and-forget write; always encrypted with this view's frozen [mode]. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T) = ksafe.putDirect(key, value, mode)

    /** Fire-and-forget write with a failure callback. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T, noinline onWriteFailed: (Throwable) -> Unit) =
        ksafe.putDirect(key, value, mode, onWriteFailed)

    /** Suspend read. Reads are mode-free — protection is auto-detected. See [KSafe.get]. */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T =
        ksafe.get(key, defaultValue)

    /** Cache read. Reads are mode-free — protection is auto-detected. See [KSafe.getDirect]. */
    inline fun <reified T> getDirect(key: String, defaultValue: T): T =
        ksafe.getDirect(key, defaultValue)

    /** Cold observable read. See [KSafe.getFlow]. */
    inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> =
        ksafe.getFlow(key, defaultValue)

    /** Hot observable read. See [KSafe.getStateFlow]. */
    inline fun <reified T> getStateFlow(key: String, defaultValue: T, scope: CoroutineScope): StateFlow<T> =
        ksafe.getStateFlow(key, defaultValue, scope)

    /** Removes the value and its key material. See [KSafe.delete]. */
    suspend fun delete(key: String) = ksafe.delete(key)

    /** Fire-and-forget removal. See [KSafe.deleteDirect]. */
    fun deleteDirect(key: String) = ksafe.deleteDirect(key)

    /**
     * Property delegate; writes always use this view's frozen [mode]. With no [key] the
     * storage key is the property's own name, exactly as with `by ksafe(...)`.
     */
    inline operator fun <reified T> invoke(
        defaultValue: T,
        key: String? = null,
    ): ReadWriteProperty<Any?, T> = ksafe.invoke(defaultValue, key, mode)

    /** Read-only cold-Flow delegate. See [KSafe.asFlow]. */
    inline fun <reified T> asFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, Flow<T>> = ksafe.asFlow(defaultValue, key)

    /** Writable cold-Flow delegate; `set` writes use the frozen [mode]. See [KSafe.asWritableFlow]. */
    inline fun <reified T> asWritableFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
        ksafe.asWritableFlow(defaultValue, key, mode)

    /** Read-only StateFlow delegate. See [KSafe.asStateFlow]. */
    inline fun <reified T> asStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, StateFlow<T>> = ksafe.asStateFlow(defaultValue, scope, key)

    /** MutableStateFlow delegate; writes use the frozen [mode]. See [KSafe.asMutableStateFlow]. */
    inline fun <reified T> asMutableStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
        ksafe.asMutableStateFlow(defaultValue, scope, key, mode)
}

/**
 * A write-mode view over an existing [KSafe]: every write made through this handle
 * *requests* [KSafeEncryptedProtection.HARDWARE_ISOLATED] (StrongBox on Android, Secure
 * Enclave on Apple platforms), with the unlock policy frozen at construction. No `mode`
 * parameter exists anywhere on this type.
 *
 * `HARDWARE_ISOLATED` is a **request, not a guarantee**: on hardware without a StrongBox /
 * Secure Enclave, KSafe degrades to the documented next-best custody and reports it —
 * check [KSafe.protectionInfo] and [KSafe.getKeyInfo] on [ksafe]. Reserve this view for
 * master passphrases and identity keys; the per-entry hardware key allocation is slower
 * than the DEFAULT tier.
 *
 * The guarantee is **write-side only** — reads are mode-free and auto-detect each entry's
 * protection. Store-scoped operations live on [ksafe]; see [KSafePlain] for the shared
 * view semantics and the DI pattern.
 */
@Stable
class KSafeHardwareIsolated(
    val ksafe: KSafe,
    requireUnlockedDevice: Boolean =
        (ksafe.defaultWriteMode as? KSafeWriteMode.Encrypted)?.requireUnlockedDevice ?: false,
) {

    /** The frozen write mode — `Encrypted(HARDWARE_ISOLATED, requireUnlockedDevice)`. */
    val mode: KSafeWriteMode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = requireUnlockedDevice,
    )

    /** Suspend write; always requests hardware isolation via the frozen [mode]. See [KSafe.put]. */
    suspend inline fun <reified T> put(key: String, value: T) = ksafe.put(key, value, mode)

    /** Fire-and-forget write; always requests hardware isolation via the frozen [mode]. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T) = ksafe.putDirect(key, value, mode)

    /** Fire-and-forget write with a failure callback. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T, noinline onWriteFailed: (Throwable) -> Unit) =
        ksafe.putDirect(key, value, mode, onWriteFailed)

    /** Suspend read. Reads are mode-free — protection is auto-detected. See [KSafe.get]. */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T =
        ksafe.get(key, defaultValue)

    /** Cache read. Reads are mode-free — protection is auto-detected. See [KSafe.getDirect]. */
    inline fun <reified T> getDirect(key: String, defaultValue: T): T =
        ksafe.getDirect(key, defaultValue)

    /** Cold observable read. See [KSafe.getFlow]. */
    inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> =
        ksafe.getFlow(key, defaultValue)

    /** Hot observable read. See [KSafe.getStateFlow]. */
    inline fun <reified T> getStateFlow(key: String, defaultValue: T, scope: CoroutineScope): StateFlow<T> =
        ksafe.getStateFlow(key, defaultValue, scope)

    /** Removes the value and its key material. See [KSafe.delete]. */
    suspend fun delete(key: String) = ksafe.delete(key)

    /** Fire-and-forget removal. See [KSafe.deleteDirect]. */
    fun deleteDirect(key: String) = ksafe.deleteDirect(key)

    /**
     * Property delegate; writes always use this view's frozen [mode]. With no [key] the
     * storage key is the property's own name, exactly as with `by ksafe(...)`.
     */
    inline operator fun <reified T> invoke(
        defaultValue: T,
        key: String? = null,
    ): ReadWriteProperty<Any?, T> = ksafe.invoke(defaultValue, key, mode)

    /** Read-only cold-Flow delegate. See [KSafe.asFlow]. */
    inline fun <reified T> asFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, Flow<T>> = ksafe.asFlow(defaultValue, key)

    /** Writable cold-Flow delegate; `set` writes use the frozen [mode]. See [KSafe.asWritableFlow]. */
    inline fun <reified T> asWritableFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
        ksafe.asWritableFlow(defaultValue, key, mode)

    /** Read-only StateFlow delegate. See [KSafe.asStateFlow]. */
    inline fun <reified T> asStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, StateFlow<T>> = ksafe.asStateFlow(defaultValue, scope, key)

    /** MutableStateFlow delegate; writes use the frozen [mode]. See [KSafe.asMutableStateFlow]. */
    inline fun <reified T> asMutableStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
        ksafe.asMutableStateFlow(defaultValue, scope, key, mode)
}

/**
 * Shorthand for a [KSafePlain] view over this instance. Each access allocates a tiny
 * two-field object; for dependency injection prefer binding the constructor once:
 * `single { KSafePlain(get()) }`.
 */
val KSafe.plain: KSafePlain get() = KSafePlain(this)

/**
 * Shorthand for a [KSafeEncrypted] view over this instance (unlock policy inherited from
 * [KSafe.defaultWriteMode]). For dependency injection prefer `single { KSafeEncrypted(get()) }`.
 */
val KSafe.encrypted: KSafeEncrypted get() = KSafeEncrypted(this)

/**
 * Shorthand for a [KSafeHardwareIsolated] view over this instance (unlock policy inherited
 * from [KSafe.defaultWriteMode]). For dependency injection prefer
 * `single { KSafeHardwareIsolated(get()) }`.
 */
val KSafe.hardwareIsolated: KSafeHardwareIsolated get() = KSafeHardwareIsolated(this)
