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
import eu.anifantakis.lib.ksafe.internal.KSafeAtomicFlag
import eu.anifantakis.lib.ksafe.internal.ksafeSynchronized
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer
import kotlin.concurrent.Volatile
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
        return ksafe.core.getDirectRaw(key ?: property.name, defaultValue, serializer) as T
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        ksafe.core.putDirectRaw(key ?: property.name, value, mode, serializer)
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
    // @Volatile + double-checked init (FEEDBACK_4 M-G): two threads on concurrent
    // FIRST access would otherwise both build the flow and one caller would hold a
    // non-canonical instance. Fast-path read stays lock-free; only first-init locks.
    @Volatile private var flow: Flow<T>? = null
    private val initLock = Any()

    override fun getValue(thisRef: Any?, property: KProperty<*>): Flow<T> {
        flow?.let { return it }
        return ksafeSynchronized(initLock) {
            flow ?: run {
                @Suppress("UNCHECKED_CAST")
                val f = ksafe.core.getFlowRaw(key ?: property.name, defaultValue, serializer) as Flow<T>
                flow = f
                f
            }
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
    // @Volatile + double-checked init (FEEDBACK_4 M-G): getStateFlowRaw calls
    // stateIn(..., SharingStarted.Eagerly), which eagerly launches a sharing
    // coroutine — so a concurrent double-init would ALSO leak an observer coroutine,
    // not just hand out a non-canonical StateFlow. The build must run inside the lock.
    @Volatile private var stateFlow: StateFlow<T>? = null
    private val initLock = Any()

    override fun getValue(thisRef: Any?, property: KProperty<*>): StateFlow<T> {
        stateFlow?.let { return it }
        return ksafeSynchronized(initLock) {
            stateFlow ?: run {
                val sf = ksafe.getStateFlowRaw(key ?: property.name, defaultValue, serializer, scope)
                stateFlow = sf
                sf
            }
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

// ── WritableKSafeFlow (Flow + set()) ─────────────────────────────────────────────

/**
 * A cold [Flow] you can also write to.
 *
 * Returned by [KSafe.asWritableFlow]. The flow side delegates to the underlying
 * [KSafe.getFlow], so collectors observe persisted changes (including external
 * writes from other parts of the app) exactly as with [KSafe.asFlow]. The
 * write side calls [KSafe.putDirect] via [set] — the new value lands in the
 * memory cache immediately and is persisted asynchronously, and any active
 * collector emits it on the next snapshot.
 *
 * Asymmetric on purpose: there is no synchronous getter. Reads happen only
 * through flow collection, which keeps the contract identical on every
 * platform (including web, where a synchronous read against a cold cache
 * would return the default rather than the persisted value).
 *
 * Use this when you want one declaration to express "observe this stored
 * value AND let me change it" without managing a [CoroutineScope] (the
 * scope-bound alternative is [KSafe.asMutableStateFlow]).
 *
 * ## Example
 * ```kotlin
 * class SettingsRepository(ksafe: KSafe) {
 *     val themeMode: WritableKSafeFlow<ThemeMode> by ksafe.asWritableFlow(ThemeMode.DEVICE)
 *
 *     fun setThemeMode(mode: ThemeMode) {
 *         themeMode.set(mode)  // persists; collectors see it on next emission
 *     }
 * }
 * ```
 */
class WritableKSafeFlow<T> @PublishedApi internal constructor(
    private val source: Flow<T>,
    private val writer: (T) -> Unit,
) : Flow<T> by source {
    /**
     * Persists [value] via [KSafe.putDirect] using the [KSafeWriteMode]
     * configured on the originating [KSafe.asWritableFlow] call. Active
     * collectors of this flow see the new value on the next emission.
     */
    fun set(value: T) {
        writer(value)
    }
}

/**
 * Non-inline delegate that lazily creates a [WritableKSafeFlow] on first access.
 * The property name is used as the storage key unless [key] is provided.
 */
@PublishedApi
internal class KSafeWritableFlowDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
    private val mode: KSafeWriteMode,
) : ReadOnlyProperty<Any?, WritableKSafeFlow<T>> {
    // @Volatile + double-checked init (FEEDBACK_4 M-G).
    @Volatile private var writable: WritableKSafeFlow<T>? = null
    private val initLock = Any()

    override fun getValue(thisRef: Any?, property: KProperty<*>): WritableKSafeFlow<T> {
        writable?.let { return it }
        return ksafeSynchronized(initLock) {
            writable ?: run {
                val actualKey = key ?: property.name
                @Suppress("UNCHECKED_CAST")
                val source = ksafe.core.getFlowRaw(actualKey, defaultValue, serializer) as Flow<T>
                val wf = WritableKSafeFlow<T>(
                    source = source,
                    writer = { newValue ->
                        ksafe.core.putDirectRaw(actualKey, newValue, mode, serializer)
                    },
                )
                writable = wf
                wf
            }
        }
    }
}

/**
 * Returns a read/write property delegate backed by a [WritableKSafeFlow] — a [Flow]
 * you can call [WritableKSafeFlow.set] on.
 *
 * Folds the common pair of declarations
 *
 * ```kotlin
 * val mode: Flow<ThemeMode>     by ksafe.asFlow(ThemeMode.DEVICE)
 * private var modeValue: ThemeMode by ksafe(ThemeMode.DEVICE, key = "mode")
 * ```
 *
 * into a single binding that exposes both halves. The property name is used
 * as the storage key unless [key] is provided. Default [mode] is encrypted —
 * matching the property delegate (`ksafe(...)`) and [asMutableStateFlow], so
 * the new API does not silently change persistence semantics.
 *
 * No [CoroutineScope] is required: the flow is cold (collected on demand by
 * the consumer's own scope), and the writer is synchronous fire-and-forget
 * via [KSafe.putDirect].
 *
 * ## Example
 * ```kotlin
 * class SettingsRepository(ksafe: KSafe) {
 *     val themeMode: WritableKSafeFlow<ThemeMode> by ksafe.asWritableFlow(ThemeMode.DEVICE)
 *
 *     fun setThemeMode(mode: ThemeMode) {
 *         themeMode.set(mode)
 *     }
 * }
 * ```
 */
inline fun <reified T> KSafe.asWritableFlow(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted(),
): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
    KSafeWritableFlowDelegate(this, serializer(), defaultValue, key, mode)

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
 * the new value via [KSafe.putDirect]. While one of your own writes is still
 * propagating to disk, lagging disk emissions are suppressed so they can't
 * momentarily revert it; reflection of external changes resumes as soon as the
 * observed flow has caught up with the written value.
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

    // Latched while the user's latest write through this StateFlow
    // (value/emit/tryEmit/compareAndSet) is still propagating to disk: stale
    // disk echoes from the observer flow must not revert it. Cleared by
    // [updateFromFlow] once the flow has caught up with [lastUserWrite], so
    // genuinely newer external changes reflect again.
    private val awaitingWriteEcho = KSafeAtomicFlag(false)

    // The user's latest written value, compared against observer emissions to
    // detect the echo. Written BEFORE the flag is raised so a concurrent
    // [updateFromFlow] that observes the flag also observes the fresh value.
    @kotlin.concurrent.Volatile
    private var lastUserWrite: T? = null

    // The value last known to be in sync with storage — what a stale/older observer
    // emission would carry. A divergence to protect exists ONLY while the written
    // value differs from this. If a write nets back to the synced value (an idempotent
    // `value = X` from a synced state, or an A→B→A toggle within one coalescing window),
    // no distinct echo can ever arrive, so the guard must NOT be raised/held — otherwise
    // external observation is suppressed permanently (deep-review M2).
    //
    // KNOWN LIMITATION (round-3 audit R7, accepted): if an intermediate value B in an
    // A→B→A sequence actually reached disk in a SEPARATE batch (not coalesced away), a
    // stale "B" snapshot can still arrive after the net-zero "A" write cleared the guard
    // and transiently revert the value — until B's follow-up "A" snapshot arrives and
    // restores it. This is a brief, self-correcting flicker, never data loss. It is the
    // accepted cost of clearing the guard on net-zero: a value-only observer cannot tell a
    // stale intermediate echo from a genuine external change, and permanently latching the
    // guard (the alternative) is the strictly worse M2 bug (external observation dies for
    // the StateFlow's lifetime). Fixing it fully needs a versioned/epoch-tagged observer.
    @kotlin.concurrent.Volatile
    private var syncedValue: T? = null
    @kotlin.concurrent.Volatile
    private var hasSynced: Boolean = false

    /**
     * Raise the echo guard only for a write that actually diverges from storage.
     * [oldValue] is the value present BEFORE this write — used to seed [syncedValue]
     * on the first write (the setter passes the pre-mutation value; compareAndSet
     * passes `expect`, which it just matched).
     */
    private fun markUserWrite(newValue: T, oldValue: T) {
        if (!hasSynced) {
            syncedValue = oldValue
            hasSynced = true
        }
        lastUserWrite = newValue
        // No net divergence → nothing to echo, nothing to protect: clear the guard.
        awaitingWriteEcho.set(newValue != syncedValue)
    }

    override var value: T
        get() = delegate.value
        set(newValue) {
            markUserWrite(newValue, delegate.value)
            delegate.value = newValue
            persist(newValue)
        }

    override fun compareAndSet(expect: T, update: T): Boolean {
        val changed = delegate.compareAndSet(expect, update)
        if (changed) {
            markUserWrite(update, expect)
            persist(update)
        }
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
     * Updates the value from an observer-flow emission without triggering persistence.
     *
     * Suppressed while the user's own write is propagating to disk: the observer
     * flow is disk-derived and lags optimistic writes by the coalescing window +
     * commit, so a snapshot emitted before the write commits carries an OLDER
     * value and applying it would revert the StateFlow under collectors.
     *
     * The suppression is precise, not permanent: once an emission equal to the
     * user's last-written value arrives, the latch clears and genuinely newer
     * external changes reflect again. Conservative residual cases (the StateFlow
     * keeps the user's value rather than reverting): a write whose batch fails
     * never echoes, and a type whose deserialized round-trip is not `==` to the
     * written instance never matches — both keep suppression in place.
     */
    /**
     * Test-only: simulates the M-F race where a stale observer emission clobbers the
     * visible value AFTER the setter armed the echo guard (the check-then-apply in
     * [updateFromFlow] is not atomic). Lets a deterministic test verify the self-heal.
     */
    @PublishedApi internal fun simulateStaleClobberForTest(staleValue: T) {
        delegate.value = staleValue
    }

    internal fun updateFromFlow(newValue: T) {
        if (!awaitingWriteEcho.get()) {
            delegate.value = newValue
            // This emission is now the in-sync baseline for future divergence checks.
            syncedValue = newValue
            hasSynced = true
            return
        }
        if (newValue == lastUserWrite) {
            // The echo of the user's own write: consume it and resume external-change
            // reflection. Re-apply the echoed value too (FEEDBACK_4 M-F, twin of the
            // Compose KSafeComposeState fix): the guard check-then-apply above is not
            // atomic against the setter, so a stale emission that read the latch as
            // false before the setter armed it can clobber the visible value AFTER the
            // setter ran. The source flow is distinctUntilChanged, so the user's value is
            // never re-emitted — without this the StateFlow would stay stuck on the stale
            // value. In the non-raced case delegate.value already equals newValue, so a
            // StateFlow's own distinct-until-changed makes this a no-op.
            delegate.value = newValue
            awaitingWriteEcho.compareAndSet(true, false)
            syncedValue = newValue
            hasSynced = true
        }
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
    // @Volatile + double-checked init (FEEDBACK_4 M-G): the init launches an observer
    // coroutine (scope.launch below), so a concurrent double-init would start TWO
    // observers — a leaked coroutine that re-decrypts on every external change — and
    // hand a losing caller a StateFlow with its own optimistic/echo state that can
    // transiently diverge. The build AND the launch run inside the lock so exactly one
    // canonical instance + observer is created.
    @Volatile private var mutableStateFlow: KSafeMutableStateFlow<T>? = null
    private val initLock = Any()

    override fun getValue(thisRef: Any?, property: KProperty<*>): MutableStateFlow<T> {
        mutableStateFlow?.let { return it }
        return ksafeSynchronized(initLock) {
            mutableStateFlow ?: run {
                val actualKey = key ?: property.name

                @Suppress("UNCHECKED_CAST")
                val initial = ksafe.core.getDirectRaw(actualKey, defaultValue, serializer) as T

                val msf = KSafeMutableStateFlow(initial) { newValue ->
                    ksafe.core.putDirectRaw(actualKey, newValue, mode, serializer)
                }

                // Observe external changes (other screens, background writes). getFlowRaw
                // skips transient decrypt failures, so a locked-device emission can't crash
                // [scope] or kill observation.
                scope.launch {
                    @Suppress("UNCHECKED_CAST")
                    (ksafe.core.getFlowRaw(actualKey, defaultValue, serializer) as Flow<T>)
                        .collect { msf.updateFromFlow(it) }
                }

                mutableStateFlow = msf
                msf
            }
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
