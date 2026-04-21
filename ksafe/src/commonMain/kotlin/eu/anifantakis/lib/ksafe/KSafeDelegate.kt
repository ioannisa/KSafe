package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.ExperimentalForInheritanceCoroutinesApi
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.FlowCollector
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer
import kotlin.properties.ReadOnlyProperty
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * Non-inline delegate class that holds a [KSerializer] captured once at creation time.
 * This prevents the entire getDirect/putDirect inline chain from being duplicated
 * at every property declaration site (~250 lines per delegate → ~5 lines).
 */
@PublishedApi
internal class KSafeDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
    private val mode: KSafeWriteMode
) : ReadWriteProperty<Any?, T> {
    override fun getValue(thisRef: Any?, property: KProperty<*>): T {
        @Suppress("UNCHECKED_CAST")
        return ksafe.getDirectRaw(key ?: property.name, defaultValue, serializer) as T
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        ksafe.putDirectRaw(key ?: property.name, value, mode, serializer)
    }
}

/**
 * Allows KSafe to be used with property delegation.
 *
 * Uses non-blocking [KSafe.getDirect]/[KSafe.putDirect] under the hood.
 * Default mode is encrypted.
 */
inline operator fun <reified T> KSafe.invoke(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted()
): ReadWriteProperty<Any?, T> = KSafeDelegate(this, serializer<T>(), defaultValue, key, mode)

// ── Flow delegates ──────────────────────────────────────────────────────────

/**
 * Non-inline delegate that lazily creates a [Flow] on first access.
 * The property name is used as the storage key unless [key] is provided.
 */
@PublishedApi
internal class KSafeFlowDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
) : ReadOnlyProperty<Any?, Flow<T>> {
    private var flow: Flow<T>? = null

    override fun getValue(thisRef: Any?, property: KProperty<*>): Flow<T> {
        return flow ?: run {
            @Suppress("UNCHECKED_CAST")
            val f = ksafe.getFlowRaw(key ?: property.name, defaultValue, serializer) as Flow<T>
            flow = f
            f
        }
    }
}

/**
 * Non-inline delegate that lazily creates a [StateFlow] on first access.
 * The property name is used as the storage key unless [key] is provided.
 */
@PublishedApi
internal class KSafeStateFlowDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
    private val scope: CoroutineScope,
) : ReadOnlyProperty<Any?, StateFlow<T>> {
    private var stateFlow: StateFlow<T>? = null

    override fun getValue(thisRef: Any?, property: KProperty<*>): StateFlow<T> {
        return stateFlow ?: run {
            val sf = ksafe.getStateFlowRaw(key ?: property.name, defaultValue, serializer, scope)
            stateFlow = sf
            sf
        }
    }
}

/**
 * Returns a read-only property delegate backed by [KSafe.getFlow].
 *
 * The property name is used as the storage key unless [key] is provided.
 * Protection is auto-detected from stored metadata.
 *
 * ## Example
 * ```kotlin
 * class UserRepository(kSafe: KSafe) {
 *     val username: Flow<String> by kSafe.asFlow(defaultValue = "Guest")
 * }
 * ```
 */
inline fun <reified T> KSafe.asFlow(
    defaultValue: T,
    key: String? = null,
): ReadOnlyProperty<Any?, Flow<T>> = KSafeFlowDelegate(this, serializer(), defaultValue, key)

/**
 * Returns a read-only property delegate backed by [KSafe.getStateFlow].
 *
 * The property name is used as the storage key unless [key] is provided.
 * The initial value is resolved synchronously via [KSafe.getDirect], preventing
 * a brief incorrect emission of the default.
 * Protection is auto-detected from stored metadata.
 *
 * ## Example
 * ```kotlin
 * class SettingsViewModel(kSafe: KSafe) : ViewModel() {
 *     val darkMode: StateFlow<Boolean> by kSafe.asStateFlow(false, viewModelScope)
 * }
 * ```
 */
inline fun <reified T> KSafe.asStateFlow(
    defaultValue: T,
    scope: CoroutineScope,
    key: String? = null,
): ReadOnlyProperty<Any?, StateFlow<T>> = KSafeStateFlowDelegate(this, serializer(), defaultValue, key, scope)

// ── MutableStateFlow delegate ───────────────────────────────────────────────

/**
 * A [MutableStateFlow] wrapper that persists values to KSafe on every write.
 *
 * External changes (from other screens, background writes, etc.) are reflected
 * automatically via flow observation in the provided [CoroutineScope].
 * Setting [value], calling [emit], [tryEmit], or [compareAndSet] will persist
 * the new value via [KSafe.putDirect].
 */
@OptIn(
    ExperimentalCoroutinesApi::class,
    InternalCoroutinesApi::class, ExperimentalForInheritanceCoroutinesApi::class,
)
@PublishedApi
internal class KSafeMutableStateFlow<T>(
    initialValue: T,
    private val persist: (T) -> Unit,
) : MutableStateFlow<T> {

    private val delegate = MutableStateFlow(initialValue)

    override var value: T
        get() = delegate.value
        set(newValue) {
            delegate.value = newValue
            persist(newValue)
        }

    override fun compareAndSet(expect: T, update: T): Boolean {
        val changed = delegate.compareAndSet(expect, update)
        if (changed) persist(update)
        return changed
    }

    override suspend fun emit(value: T) {
        this.value = value
    }

    override fun tryEmit(value: T): Boolean {
        this.value = value
        return true
    }

    override val subscriptionCount: StateFlow<Int> get() = delegate.subscriptionCount
    override val replayCache: List<T> get() = delegate.replayCache

    override suspend fun collect(collector: FlowCollector<T>): Nothing =
        delegate.collect(collector)

    @Suppress("OVERRIDE_DEPRECATION")
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    override fun resetReplayCache() = delegate.resetReplayCache()

    /**
     * Updates the value from a flow emission without triggering persistence.
     */
    internal fun updateFromFlow(newValue: T) {
        delegate.value = newValue
    }
}

/**
 * Non-inline delegate that lazily creates a [KSafeMutableStateFlow] on first access.
 * The property name is used as the storage key unless [key] is provided.
 */
@PublishedApi
internal class KSafeMutableStateFlowDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
    private val scope: CoroutineScope,
    private val mode: KSafeWriteMode,
) : ReadOnlyProperty<Any?, MutableStateFlow<T>> {
    private var mutableStateFlow: KSafeMutableStateFlow<T>? = null

    override fun getValue(thisRef: Any?, property: KProperty<*>): MutableStateFlow<T> {
        return mutableStateFlow ?: run {
            val actualKey = key ?: property.name

            @Suppress("UNCHECKED_CAST")
            val initial = ksafe.getDirectRaw(actualKey, defaultValue, serializer) as T

            val msf = KSafeMutableStateFlow(initial) { newValue ->
                ksafe.putDirectRaw(actualKey, newValue, mode, serializer)
            }

            // Observe external changes (other screens, background writes)
            scope.launch {
                @Suppress("UNCHECKED_CAST")
                (ksafe.getFlowRaw(actualKey, defaultValue, serializer) as Flow<T>)
                    .collect { msf.updateFromFlow(it) }
            }

            mutableStateFlow = msf
            msf
        }
    }
}

/**
 * Returns a read/write property delegate backed by a [MutableStateFlow] that
 * persists values to KSafe on every write.
 *
 * The property name is used as the storage key unless [key] is provided.
 * External changes are automatically reflected via flow observation in [scope].
 * Protection is auto-detected for reads; writes use the specified [mode].
 *
 * ## Example
 * ```kotlin
 * class SettingsViewModel(kSafe: KSafe) : ViewModel() {
 *     val username: MutableStateFlow<String> by kSafe.asMutableStateFlow("Guest", viewModelScope)
 *
 *     fun updateName(name: String) {
 *         username.value = name  // persists + emits to all collectors
 *     }
 * }
 * ```
 */
inline fun <reified T> KSafe.asMutableStateFlow(
    defaultValue: T,
    scope: CoroutineScope,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted(),
): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
    KSafeMutableStateFlowDelegate(this, serializer(), defaultValue, key, scope, mode)

/** @deprecated Use [invoke] with [KSafeWriteMode] parameter instead. */
@Deprecated(
    "Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain",
    ReplaceWith("invoke(defaultValue, key, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)")
)
inline operator fun <reified T> KSafe.invoke(
    defaultValue: T,
    key: String? = null,
    encrypted: Boolean
): ReadWriteProperty<Any?, T> =
    invoke(defaultValue, key, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)
