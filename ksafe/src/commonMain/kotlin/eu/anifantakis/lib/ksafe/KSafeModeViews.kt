package eu.anifantakis.lib.ksafe

import androidx.compose.runtime.Stable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.properties.ReadOnlyProperty

/**
 * A view sharing [ksafe]'s store and cache, whose every write is [KSafeWriteMode.Plain].
 * Write-side only: reads carry no mode and auto-detect each entry's protection. Store-wide
 * operations (rotateKeys, clearAll, close, protectionInfo, …) live on [ksafe].
 */
@Stable
class KSafePlain(val ksafe: KSafe) {

    /** Always [KSafeWriteMode.Plain]. */
    val mode: KSafeWriteMode get() = KSafeWriteMode.Plain

    /** Suspend write in this view's [mode]. See [KSafe.put]. */
    suspend inline fun <reified T> put(key: String, value: T) =
        ksafe.put(key, value, KSafeWriteMode.Plain)

    /** Fire-and-forget write in this view's [mode]. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T) =
        ksafe.putDirect(key, value, KSafeWriteMode.Plain)

    /** Fire-and-forget write with a failure callback. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T, noinline onWriteFailed: (Throwable) -> Unit) =
        ksafe.putDirect(key, value, KSafeWriteMode.Plain, onWriteFailed)

    /** Suspend read; protection is auto-detected. See [KSafe.get]. */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T =
        ksafe.get(key, defaultValue)

    /** Cache read; protection is auto-detected. See [KSafe.getDirect]. */
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

    /** Delegate, or a direct handle via [KSafeReference.value]; [key] defaults to the property name. */
    inline operator fun <reified T> invoke(
        defaultValue: T,
        key: String? = null,
    ): KSafeReference<T> = ksafe.invoke(defaultValue, key, KSafeWriteMode.Plain)

    /** Read-only cold-Flow delegate. See [KSafe.asFlow]. */
    inline fun <reified T> asFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, Flow<T>> = ksafe.asFlow(defaultValue, key)

    /** Writable cold-Flow delegate; `set` writes use this view's [mode]. See [KSafe.asWritableFlow]. */
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

    /** MutableStateFlow delegate; writes use this view's [mode]. See [KSafe.asMutableStateFlow]. */
    inline fun <reified T> asMutableStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
        ksafe.asMutableStateFlow(defaultValue, scope, key, KSafeWriteMode.Plain)
}

/**
 * Like [KSafePlain], but every write is [KSafeWriteMode.Encrypted] at the
 * [KSafeEncryptedProtection.DEFAULT] tier. [requireUnlockedDevice] defaults to the
 * instance's own policy, so this view matches a modeless `ksafe.put`.
 */
@Stable
class KSafeEncrypted(
    val ksafe: KSafe,
    requireUnlockedDevice: Boolean =
        (ksafe.defaultWriteMode as? KSafeWriteMode.Encrypted)?.requireUnlockedDevice ?: false,
) {

    /** Always `Encrypted(DEFAULT, requireUnlockedDevice)`. */
    val mode: KSafeWriteMode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.DEFAULT,
        requireUnlockedDevice = requireUnlockedDevice,
    )

    /** Suspend write in this view's [mode]. See [KSafe.put]. */
    suspend inline fun <reified T> put(key: String, value: T) = ksafe.put(key, value, mode)

    /** Fire-and-forget write in this view's [mode]. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T) = ksafe.putDirect(key, value, mode)

    /** Fire-and-forget write with a failure callback. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T, noinline onWriteFailed: (Throwable) -> Unit) =
        ksafe.putDirect(key, value, mode, onWriteFailed)

    /** Suspend read; protection is auto-detected. See [KSafe.get]. */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T =
        ksafe.get(key, defaultValue)

    /** Cache read; protection is auto-detected. See [KSafe.getDirect]. */
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

    /** Delegate, or a direct handle via [KSafeReference.value]; [key] defaults to the property name. */
    inline operator fun <reified T> invoke(
        defaultValue: T,
        key: String? = null,
    ): KSafeReference<T> = ksafe.invoke(defaultValue, key, mode)

    /** Read-only cold-Flow delegate. See [KSafe.asFlow]. */
    inline fun <reified T> asFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, Flow<T>> = ksafe.asFlow(defaultValue, key)

    /** Writable cold-Flow delegate; `set` writes use this view's [mode]. See [KSafe.asWritableFlow]. */
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

    /** MutableStateFlow delegate; writes use this view's [mode]. See [KSafe.asMutableStateFlow]. */
    inline fun <reified T> asMutableStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
        ksafe.asMutableStateFlow(defaultValue, scope, key, mode)
}

/**
 * Like [KSafePlain], but every write requests [KSafeEncryptedProtection.HARDWARE_ISOLATED]
 * (StrongBox / Secure Enclave). A request, not a guarantee: without that hardware KSafe
 * degrades to the next-best custody and reports it via [KSafe.protectionInfo]. Slower than
 * the DEFAULT tier, so reserve it for master passphrases and identity keys.
 */
@Stable
class KSafeHardwareIsolated(
    val ksafe: KSafe,
    requireUnlockedDevice: Boolean =
        (ksafe.defaultWriteMode as? KSafeWriteMode.Encrypted)?.requireUnlockedDevice ?: false,
) {

    /** Always `Encrypted(HARDWARE_ISOLATED, requireUnlockedDevice)`. */
    val mode: KSafeWriteMode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = requireUnlockedDevice,
    )

    /** Suspend write in this view's [mode]. See [KSafe.put]. */
    suspend inline fun <reified T> put(key: String, value: T) = ksafe.put(key, value, mode)

    /** Fire-and-forget write in this view's [mode]. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T) = ksafe.putDirect(key, value, mode)

    /** Fire-and-forget write with a failure callback. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T, noinline onWriteFailed: (Throwable) -> Unit) =
        ksafe.putDirect(key, value, mode, onWriteFailed)

    /** Suspend read; protection is auto-detected. See [KSafe.get]. */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T =
        ksafe.get(key, defaultValue)

    /** Cache read; protection is auto-detected. See [KSafe.getDirect]. */
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

    /** Delegate, or a direct handle via [KSafeReference.value]; [key] defaults to the property name. */
    inline operator fun <reified T> invoke(
        defaultValue: T,
        key: String? = null,
    ): KSafeReference<T> = ksafe.invoke(defaultValue, key, mode)

    /** Read-only cold-Flow delegate. See [KSafe.asFlow]. */
    inline fun <reified T> asFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, Flow<T>> = ksafe.asFlow(defaultValue, key)

    /** Writable cold-Flow delegate; `set` writes use this view's [mode]. See [KSafe.asWritableFlow]. */
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

    /** MutableStateFlow delegate; writes use this view's [mode]. See [KSafe.asMutableStateFlow]. */
    inline fun <reified T> asMutableStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
        ksafe.asMutableStateFlow(defaultValue, scope, key, mode)
}

/** A [KSafePlain] view over this instance; each access allocates a new one. */
val KSafe.plain: KSafePlain get() = KSafePlain(this)

/** A [KSafeEncrypted] view over this instance, inheriting its unlock policy. */
val KSafe.encrypted: KSafeEncrypted get() = KSafeEncrypted(this)

/** A [KSafeHardwareIsolated] view over this instance, inheriting its unlock policy. */
val KSafe.hardwareIsolated: KSafeHardwareIsolated get() = KSafeHardwareIsolated(this)
