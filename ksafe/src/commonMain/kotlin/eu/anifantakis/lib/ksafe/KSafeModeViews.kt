package eu.anifantakis.lib.ksafe

import androidx.compose.runtime.Stable
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.properties.ReadOnlyProperty

/**
 * A view over [ksafe] whose every write is [KSafeWriteMode.Plain], so a call site has no `mode`
 * argument to get wrong. Inject it where a component should only store non-secret preferences.
 * Views share the store and cache: a value written here is immediately visible through [ksafe]
 * and every other view.
 *
 * Write-side only: reads carry no mode and auto-detect each entry's protection, so [get] also
 * returns values another handle wrote encrypted. Store-wide operations ([KSafe.rotateKeys],
 * [KSafe.clearAll], [KSafe.close], [KSafe.protectionInfo], …) live on [ksafe].
 *
 * @property ksafe The underlying instance; store-wide operations go through it.
 */
@Stable
class KSafePlain(val ksafe: KSafe) {

    /** The mode every write through this view uses: always [KSafeWriteMode.Plain]. */
    val mode: KSafeWriteMode get() = KSafeWriteMode.Plain

    /** Persists [value] in this view's [mode], suspending until committed. See [KSafe.put]. */
    suspend inline fun <reified T> put(key: String, value: T) =
        ksafe.put(key, value, KSafeWriteMode.Plain)

    /** Fire-and-forget write in this view's [mode], with an optimistic cache update. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T) =
        ksafe.putDirect(key, value, KSafeWriteMode.Plain)

    /** [putDirect] plus [onWriteFailed], called once if the background persist fails. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T, noinline onWriteFailed: (Throwable) -> Unit) =
        ksafe.putDirect(key, value, KSafeWriteMode.Plain, onWriteFailed)

    /** Suspending read; the entry's protection is auto-detected, whichever handle wrote it.
     *  See [KSafe.get]. */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T =
        ksafe.get(key, defaultValue)

    /** Cache read, blocking once while the cache loads; protection is auto-detected. See [KSafe.getDirect]. */
    inline fun <reified T> getDirect(key: String, defaultValue: T): T =
        ksafe.getDirect(key, defaultValue)

    /** Cold [Flow] of the value and its updates. See [KSafe.getFlow]. */
    inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> =
        ksafe.getFlow(key, defaultValue)

    /** Hot [StateFlow] shared eagerly in [scope]. See [KSafe.getStateFlow]. */
    inline fun <reified T> getStateFlow(key: String, defaultValue: T, scope: CoroutineScope): StateFlow<T> =
        ksafe.getStateFlow(key, defaultValue, scope)

    /** Removes the value and its key material, suspending until done. See [KSafe.delete]. */
    suspend fun delete(key: String) = ksafe.delete(key)

    /** Fire-and-forget removal; the cache updates now. See [KSafe.deleteDirect]. */
    fun deleteDirect(key: String) = ksafe.deleteDirect(key)

    /** Property delegate, or a handle used via [KSafeReference.value] when [key] is given; writes
     *  use this view's [mode]. See [KSafe.invoke]. */
    inline operator fun <reified T> invoke(
        defaultValue: T,
        key: String? = null,
    ): KSafeReference<T> = ksafe.invoke(defaultValue, key, KSafeWriteMode.Plain)

    /** Read-only delegate yielding a cold [Flow]. See [KSafe.asFlow]. */
    inline fun <reified T> asFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, Flow<T>> = ksafe.asFlow(defaultValue, key)

    /** Delegate yielding a [WritableKSafeFlow]; [WritableKSafeFlow.set] writes in this view's [mode].
     *  See [KSafe.asWritableFlow]. */
    inline fun <reified T> asWritableFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
        ksafe.asWritableFlow(defaultValue, key, KSafeWriteMode.Plain)

    /** Read-only delegate yielding a hot [StateFlow] shared in [scope]. See [KSafe.asStateFlow]. */
    inline fun <reified T> asStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, StateFlow<T>> = ksafe.asStateFlow(defaultValue, scope, key)

    /** Delegate yielding a persisting [MutableStateFlow]; writes use this view's [mode].
     *  See [KSafe.asMutableStateFlow]. */
    inline fun <reified T> asMutableStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
        ksafe.asMutableStateFlow(defaultValue, scope, key, KSafeWriteMode.Plain)
}

/**
 * Like [KSafePlain], but every write is [KSafeWriteMode.Encrypted] at the
 * [KSafeEncryptedProtection.DEFAULT] tier. Inject it where a component stores secrets that
 * need no hardware isolation.
 *
 * @property ksafe The underlying instance; store-wide operations go through it.
 * @param requireUnlockedDevice Unlock policy for every write; defaults to [ksafe]'s own
 *   ([KSafeConfig.requireUnlockedDevice]), so this view writes exactly like a modeless `ksafe.put`.
 *   See [KSafeWriteMode.Encrypted.requireUnlockedDevice] for the platform caveats.
 */
@Stable
class KSafeEncrypted(
    val ksafe: KSafe,
    requireUnlockedDevice: Boolean =
        (ksafe.defaultWriteMode as? KSafeWriteMode.Encrypted)?.requireUnlockedDevice ?: false,
) {

    /** The mode every write through this view uses: `Encrypted(DEFAULT, requireUnlockedDevice)`. */
    val mode: KSafeWriteMode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.DEFAULT,
        requireUnlockedDevice = requireUnlockedDevice,
    )

    /** Persists [value] in this view's [mode], suspending until committed. See [KSafe.put]. */
    suspend inline fun <reified T> put(key: String, value: T) = ksafe.put(key, value, mode)

    /** Fire-and-forget write in this view's [mode], with an optimistic cache update. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T) = ksafe.putDirect(key, value, mode)

    /** [putDirect] plus [onWriteFailed], called once if the background persist fails. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T, noinline onWriteFailed: (Throwable) -> Unit) =
        ksafe.putDirect(key, value, mode, onWriteFailed)

    /** Suspending read; the entry's protection is auto-detected, whichever handle wrote it.
     *  See [KSafe.get]. */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T =
        ksafe.get(key, defaultValue)

    /** Cache read, blocking once while the cache loads; protection is auto-detected. See [KSafe.getDirect]. */
    inline fun <reified T> getDirect(key: String, defaultValue: T): T =
        ksafe.getDirect(key, defaultValue)

    /** Cold [Flow] of the value and its updates. See [KSafe.getFlow]. */
    inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> =
        ksafe.getFlow(key, defaultValue)

    /** Hot [StateFlow] shared eagerly in [scope]. See [KSafe.getStateFlow]. */
    inline fun <reified T> getStateFlow(key: String, defaultValue: T, scope: CoroutineScope): StateFlow<T> =
        ksafe.getStateFlow(key, defaultValue, scope)

    /** Removes the value and its key material, suspending until done. See [KSafe.delete]. */
    suspend fun delete(key: String) = ksafe.delete(key)

    /** Fire-and-forget removal; the cache updates now. See [KSafe.deleteDirect]. */
    fun deleteDirect(key: String) = ksafe.deleteDirect(key)

    /** Property delegate, or a handle used via [KSafeReference.value] when [key] is given; writes
     *  use this view's [mode]. See [KSafe.invoke]. */
    inline operator fun <reified T> invoke(
        defaultValue: T,
        key: String? = null,
    ): KSafeReference<T> = ksafe.invoke(defaultValue, key, mode)

    /** Read-only delegate yielding a cold [Flow]. See [KSafe.asFlow]. */
    inline fun <reified T> asFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, Flow<T>> = ksafe.asFlow(defaultValue, key)

    /** Delegate yielding a [WritableKSafeFlow]; [WritableKSafeFlow.set] writes in this view's [mode].
     *  See [KSafe.asWritableFlow]. */
    inline fun <reified T> asWritableFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
        ksafe.asWritableFlow(defaultValue, key, mode)

    /** Read-only delegate yielding a hot [StateFlow] shared in [scope]. See [KSafe.asStateFlow]. */
    inline fun <reified T> asStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, StateFlow<T>> = ksafe.asStateFlow(defaultValue, scope, key)

    /** Delegate yielding a persisting [MutableStateFlow]; writes use this view's [mode].
     *  See [KSafe.asMutableStateFlow]. */
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
 * falls back to the next-best custody and reports it via [KSafe.protectionInfo]. Slower than
 * the DEFAULT tier, so reserve it for master passphrases and identity keys.
 *
 * @property ksafe The underlying instance; store-wide operations go through it.
 * @param requireUnlockedDevice Unlock policy for every write; defaults to [ksafe]'s own
 *   ([KSafeConfig.requireUnlockedDevice]). See [KSafeWriteMode.Encrypted.requireUnlockedDevice]
 *   for the platform caveats.
 */
@Stable
class KSafeHardwareIsolated(
    val ksafe: KSafe,
    requireUnlockedDevice: Boolean =
        (ksafe.defaultWriteMode as? KSafeWriteMode.Encrypted)?.requireUnlockedDevice ?: false,
) {

    /** The mode every write through this view uses: `Encrypted(HARDWARE_ISOLATED, requireUnlockedDevice)`. */
    val mode: KSafeWriteMode = KSafeWriteMode.Encrypted(
        protection = KSafeEncryptedProtection.HARDWARE_ISOLATED,
        requireUnlockedDevice = requireUnlockedDevice,
    )

    /** Persists [value] in this view's [mode], suspending until committed. See [KSafe.put]. */
    suspend inline fun <reified T> put(key: String, value: T) = ksafe.put(key, value, mode)

    /** Fire-and-forget write in this view's [mode], with an optimistic cache update. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T) = ksafe.putDirect(key, value, mode)

    /** [putDirect] plus [onWriteFailed], called once if the background persist fails. See [KSafe.putDirect]. */
    inline fun <reified T> putDirect(key: String, value: T, noinline onWriteFailed: (Throwable) -> Unit) =
        ksafe.putDirect(key, value, mode, onWriteFailed)

    /** Suspending read; the entry's protection is auto-detected, whichever handle wrote it.
     *  See [KSafe.get]. */
    suspend inline fun <reified T> get(key: String, defaultValue: T): T =
        ksafe.get(key, defaultValue)

    /** Cache read, blocking once while the cache loads; protection is auto-detected. See [KSafe.getDirect]. */
    inline fun <reified T> getDirect(key: String, defaultValue: T): T =
        ksafe.getDirect(key, defaultValue)

    /** Cold [Flow] of the value and its updates. See [KSafe.getFlow]. */
    inline fun <reified T> getFlow(key: String, defaultValue: T): Flow<T> =
        ksafe.getFlow(key, defaultValue)

    /** Hot [StateFlow] shared eagerly in [scope]. See [KSafe.getStateFlow]. */
    inline fun <reified T> getStateFlow(key: String, defaultValue: T, scope: CoroutineScope): StateFlow<T> =
        ksafe.getStateFlow(key, defaultValue, scope)

    /** Removes the value and its key material, suspending until done. See [KSafe.delete]. */
    suspend fun delete(key: String) = ksafe.delete(key)

    /** Fire-and-forget removal; the cache updates now. See [KSafe.deleteDirect]. */
    fun deleteDirect(key: String) = ksafe.deleteDirect(key)

    /** Property delegate, or a handle used via [KSafeReference.value] when [key] is given; writes
     *  use this view's [mode]. See [KSafe.invoke]. */
    inline operator fun <reified T> invoke(
        defaultValue: T,
        key: String? = null,
    ): KSafeReference<T> = ksafe.invoke(defaultValue, key, mode)

    /** Read-only delegate yielding a cold [Flow]. See [KSafe.asFlow]. */
    inline fun <reified T> asFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, Flow<T>> = ksafe.asFlow(defaultValue, key)

    /** Delegate yielding a [WritableKSafeFlow]; [WritableKSafeFlow.set] writes in this view's [mode].
     *  See [KSafe.asWritableFlow]. */
    inline fun <reified T> asWritableFlow(
        defaultValue: T,
        key: String? = null,
    ): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
        ksafe.asWritableFlow(defaultValue, key, mode)

    /** Read-only delegate yielding a hot [StateFlow] shared in [scope]. See [KSafe.asStateFlow]. */
    inline fun <reified T> asStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, StateFlow<T>> = ksafe.asStateFlow(defaultValue, scope, key)

    /** Delegate yielding a persisting [MutableStateFlow]; writes use this view's [mode].
     *  See [KSafe.asMutableStateFlow]. */
    inline fun <reified T> asMutableStateFlow(
        defaultValue: T,
        scope: CoroutineScope,
        key: String? = null,
    ): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
        ksafe.asMutableStateFlow(defaultValue, scope, key, mode)
}

/** A new [KSafePlain] view over this instance on every access. */
val KSafe.plain: KSafePlain get() = KSafePlain(this)

/** A new [KSafeEncrypted] view over this instance on every access, using its unlock policy. */
val KSafe.encrypted: KSafeEncrypted get() = KSafeEncrypted(this)

/** A new [KSafeHardwareIsolated] view over this instance on every access, using its unlock policy. */
val KSafe.hardwareIsolated: KSafeHardwareIsolated get() = KSafeHardwareIsolated(this)
