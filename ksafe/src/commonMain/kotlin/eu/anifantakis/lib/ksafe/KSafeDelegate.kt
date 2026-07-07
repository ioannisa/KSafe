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
import eu.anifantakis.lib.ksafe.internal.KSafeInitLock
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
    // Double-checked init: concurrent first accesses must not each build a flow,
    // or one caller would hold a non-canonical instance. Fast path stays lock-free.
    @Volatile private var flow: Flow<T>? = null
    private val initLock = KSafeInitLock()

    override fun getValue(thisRef: Any?, property: KProperty<*>): Flow<T> {
        flow?.let { return it }
        return initLock.withLock {
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
    // Double-checked init. getStateFlowRaw calls stateIn(..., Eagerly), which
    // launches a sharing coroutine — a concurrent double-init would leak one —
    // so the build must run inside the lock.
    @Volatile private var stateFlow: StateFlow<T>? = null
    private val initLock = KSafeInitLock()

    override fun getValue(thisRef: Any?, property: KProperty<*>): StateFlow<T> {
        stateFlow?.let { return it }
        return initLock.withLock {
            stateFlow ?: run {
                val sf = ksafe.getStateFlowRaw(key ?: property.name, defaultValue, serializer, scope)
                stateFlow = sf
                sf
            }
        }
    }
}

/**
 * Returns a read-only property delegate backed by [KSafe.getFlow]. The
 * property name is used as the storage key unless [key] is provided.
 */
inline fun <reified T> KSafe.asFlow(
    defaultValue: T,
    key: String? = null,
): ReadOnlyProperty<Any?, Flow<T>> = KSafeFlowDelegate(this, serializer(), defaultValue, key)

// ── WritableKSafeFlow (Flow + set()) ─────────────────────────────────────────────

/**
 * A cold [Flow] you can also write to, returned by [KSafe.asWritableFlow].
 * Collection observes persisted changes as with [KSafe.asFlow]; [set] persists
 * via [KSafe.putDirect]. There is deliberately no synchronous getter — reads
 * happen only through collection, keeping the contract identical on every
 * platform (a synchronous read against a cold web cache would return the
 * default instead of the persisted value).
 */
class WritableKSafeFlow<T> @PublishedApi internal constructor(
    private val source: Flow<T>,
    private val writer: (T) -> Unit,
) : Flow<T> by source {
    /**
     * Persists [value] using the [KSafeWriteMode] configured on the originating
     * [KSafe.asWritableFlow] call; collectors see it on the next emission.
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
    // Double-checked init so all callers share one canonical instance.
    @Volatile private var writable: WritableKSafeFlow<T>? = null
    private val initLock = KSafeInitLock()

    override fun getValue(thisRef: Any?, property: KProperty<*>): WritableKSafeFlow<T> {
        writable?.let { return it }
        return initLock.withLock {
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
 * Returns a property delegate backed by a [WritableKSafeFlow] — a [Flow] you
 * can also call [WritableKSafeFlow.set] on. The property name is used as the
 * storage key unless [key] is provided. No [CoroutineScope] is required: the
 * flow is cold and the writer is fire-and-forget via [KSafe.putDirect].
 * Default [mode] is encrypted, matching the other delegates.
 */
inline fun <reified T> KSafe.asWritableFlow(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted(),
): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
    KSafeWritableFlowDelegate(this, serializer(), defaultValue, key, mode)

/**
 * Returns a read-only property delegate backed by [KSafe.getStateFlow]. The
 * property name is used as the storage key unless [key] is provided. The
 * initial value is resolved synchronously via [KSafe.getDirect], preventing a
 * brief incorrect emission of the default.
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

    // Serializes the echo bookkeeping: every mutation of the (lastUserWrite,
    // syncedValue, hasSynced, awaitingWriteEcho) tuple runs under this lock so
    // concurrent writers never observe a half-updated tuple. persist() runs
    // outside the lock (never hold a lock across I/O).
    private val writeLock = KSafeInitLock()

    // Latched while the user's latest write is still propagating to disk, so
    // stale disk echoes from the observer flow can't revert it. Cleared by
    // [updateFromFlow] once the flow catches up with [lastUserWrite].
    private val awaitingWriteEcho = KSafeAtomicFlag(false)

    // The user's latest written value, compared against observer emissions to
    // detect the echo. Written BEFORE the flag is raised so a concurrent
    // [updateFromFlow] that observes the flag also observes the fresh value.
    @kotlin.concurrent.Volatile
    private var lastUserWrite: T? = null

    // The value last known to be in sync with storage. The guard is raised only
    // while the written value differs from this: a write that nets back to the
    // synced value (idempotent set, or A→B→A within one coalescing window)
    // produces no distinct echo, so holding the guard would suppress external
    // observation permanently. Accepted trade-off: if an intermediate B reached
    // disk in a separate batch, its stale snapshot can transiently revert a
    // net-zero write until the follow-up snapshot restores it — a brief,
    // self-correcting flicker, never data loss.
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
            writeLock.withLock {
                markUserWrite(newValue, delegate.value)
                betweenMarkAndPublishForTest?.invoke()
                delegate.value = newValue
            }
            persist(newValue)
        }

    override fun compareAndSet(expect: T, update: T): Boolean {
        val changed = writeLock.withLock {
            val c = delegate.compareAndSet(expect, update)
            if (c) markUserWrite(update, expect)
            c
        }
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
     * Test-only: simulates a stale observer emission clobbering the visible
     * value after the setter armed the echo guard, so a deterministic test can
     * verify the self-heal in [updateFromFlow].
     */
    @PublishedApi internal fun simulateStaleClobberForTest(staleValue: T) {
        delegate.value = staleValue
    }

    /**
     * Test-only: invoked inside the write lock, after markUserWrite and before
     * the delegate.value publish, so a test can verify a concurrent writer is
     * serialized rather than interleaving. Null in production.
     */
    @PublishedApi internal var betweenMarkAndPublishForTest: (() -> Unit)? = null

    /**
     * Applies an observer-flow emission without triggering persistence.
     * While the user's own write is propagating to disk, lagging disk snapshots
     * are suppressed so they can't revert it; once the emission equal to
     * [lastUserWrite] arrives the latch clears and external changes reflect
     * again. Runs under [writeLock] to stay consistent with concurrent setters.
     */
    internal fun updateFromFlow(newValue: T) {
        writeLock.withLock {
            if (!awaitingWriteEcho.get()) {
                delegate.value = newValue
                // This emission is now the in-sync baseline for divergence checks.
                syncedValue = newValue
                hasSynced = true
            } else if (newValue == lastUserWrite) {
                // The echo of the user's own write: consume it and resume external-change
                // reflection. Re-apply the value too: the guard check-then-apply is not
                // atomic against the setter, so a stale emission that read the latch as
                // false can clobber the visible value after the setter ran — and the
                // distinctUntilChanged source never re-emits the user's value, so without
                // this the StateFlow would stay stuck on the stale value. In the non-raced
                // case delegate.value already equals newValue and this is a no-op.
                delegate.value = newValue
                awaitingWriteEcho.compareAndSet(true, false)
                syncedValue = newValue
                hasSynced = true
            }
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
    // Double-checked init. Initialization launches an observer coroutine, so a
    // concurrent double-init would leak a second observer and hand one caller a
    // divergent StateFlow; the build AND the launch run inside the lock.
    @Volatile private var mutableStateFlow: KSafeMutableStateFlow<T>? = null
    private val initLock = KSafeInitLock()

    override fun getValue(thisRef: Any?, property: KProperty<*>): MutableStateFlow<T> {
        mutableStateFlow?.let { return it }
        return initLock.withLock {
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
 * Returns a property delegate backed by a [MutableStateFlow] that persists
 * values to KSafe on every write. The property name is used as the storage key
 * unless [key] is provided; external changes are reflected via flow
 * observation in [scope]. Writes use the specified [mode].
 */
inline fun <reified T> KSafe.asMutableStateFlow(
    defaultValue: T,
    scope: CoroutineScope,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted(),
): ReadOnlyProperty<Any?, MutableStateFlow<T>> =
    KSafeMutableStateFlowDelegate(this, serializer(), defaultValue, key, scope, mode)

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
