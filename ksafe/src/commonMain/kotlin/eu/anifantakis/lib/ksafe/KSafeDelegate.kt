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
import eu.anifantakis.lib.ksafe.internal.KSafeLazyRef
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer
import kotlin.concurrent.Volatile
import kotlin.properties.ReadOnlyProperty
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/** Superseded by [KSafeReference]; kept so already-inlined call sites keep linking. */
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
 * Property-delegate access to KSafe via [KSafe.getDirect]/[KSafe.putDirect]. The returned
 * [KSafeReference] can also be held in a `val` and read through [KSafeReference.value].
 */
inline operator fun <reified T> KSafe.invoke(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = core.defaultEncryptedMode()
): KSafeReference<T> = KSafeReference(this, serializer<T>(), defaultValue, key, mode)

@PublishedApi
internal class KSafeFlowDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
) : ReadOnlyProperty<Any?, Flow<T>> {
    private val flow = KSafeLazyRef<Flow<T>>()

    override fun getValue(thisRef: Any?, property: KProperty<*>): Flow<T> = flow.getOrPut {
        @Suppress("UNCHECKED_CAST")
        ksafe.core.getFlowRaw(key ?: property.name, defaultValue, serializer) as Flow<T>
    }
}

@PublishedApi
internal class KSafeStateFlowDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
    private val scope: CoroutineScope,
) : ReadOnlyProperty<Any?, StateFlow<T>> {
    // stateIn(Eagerly) launches a coroutine, so a concurrent double-init would leak one.
    private val stateFlow = KSafeLazyRef<StateFlow<T>>()

    override fun getValue(thisRef: Any?, property: KProperty<*>): StateFlow<T> = stateFlow.getOrPut {
        ksafe.getStateFlowRaw(key ?: property.name, defaultValue, serializer, scope)
    }
}

/** Read-only delegate backed by [KSafe.getFlow]; the property name is the key unless [key] is given. */
inline fun <reified T> KSafe.asFlow(
    defaultValue: T,
    key: String? = null,
): ReadOnlyProperty<Any?, Flow<T>> = KSafeFlowDelegate(this, serializer(), defaultValue, key)

/** A cold [Flow] you can also write to; [set] persists. No sync getter: a cold web cache read returns the default. */
class WritableKSafeFlow<T> @PublishedApi internal constructor(
    private val source: Flow<T>,
    private val writer: (T) -> Unit,
) : Flow<T> by source {
    /** Persists [value]; collectors see it on the next emission. */
    fun set(value: T) {
        writer(value)
    }
}

@PublishedApi
internal class KSafeWritableFlowDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
    private val mode: KSafeWriteMode,
) : ReadOnlyProperty<Any?, WritableKSafeFlow<T>> {
    private val writable = KSafeLazyRef<WritableKSafeFlow<T>>()

    override fun getValue(thisRef: Any?, property: KProperty<*>): WritableKSafeFlow<T> =
        writable.getOrPut {
            val actualKey = key ?: property.name
            @Suppress("UNCHECKED_CAST")
            val source = ksafe.core.getFlowRaw(actualKey, defaultValue, serializer) as Flow<T>
            WritableKSafeFlow<T>(
                source = source,
                writer = { newValue ->
                    ksafe.core.putDirectRaw(actualKey, newValue, mode, serializer)
                },
            )
        }
}

/**
 * Delegate backed by a [WritableKSafeFlow]; property name is the key unless [key] is given, and
 * [mode] defaults to encrypted. On Web, only writes through this same [KSafe] instance are seen.
 */
inline fun <reified T> KSafe.asWritableFlow(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = core.defaultEncryptedMode(),
): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
    KSafeWritableFlowDelegate(this, serializer(), defaultValue, key, mode)

/** Delegate backed by [KSafe.getStateFlow]; property name is the key unless [key] is given, initial value read synchronously. */
inline fun <reified T> KSafe.asStateFlow(
    defaultValue: T,
    scope: CoroutineScope,
    key: String? = null,
): ReadOnlyProperty<Any?, StateFlow<T>> = KSafeStateFlowDelegate(this, serializer(), defaultValue, key, scope)

/**
 * A [MutableStateFlow] that persists every write and reflects external changes. Disk emissions
 * lagging an in-flight write are suppressed, and a failed persist reverts to the durable value.
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

    // persist() runs INSIDE the lock — it only enqueues, no I/O. Enqueuing outside lets two racing
    // writers publish A→B but enqueue B→A, leaving the discarded value the durable one.
    private val writeLock = KSafeInitLock()

    // Latched while the user's latest write propagates, so stale disk echoes can't revert it.
    private val awaitingWriteEcho = KSafeAtomicFlag(false)

    // Written BEFORE the flag is raised, so a concurrent updateFromFlow sees the fresh value.
    @kotlin.concurrent.Volatile
    private var lastUserWrite: T? = null

    // The guard is raised only while the written value differs from this, so a net-zero write
    // (A→B→A) producing no distinct echo can't suppress external observation forever.
    @kotlin.concurrent.Volatile
    private var syncedValue: T = initialValue

    // The fallback for a durable re-read that can't resolve: a strict entry on a locked device
    // reads back as the caller's default, so the default would blank a value intact on disk.
    internal val lastSyncedValue: T get() = syncedValue

    private fun markUserWrite(newValue: T) {
        lastUserWrite = newValue
        awaitingWriteEcho.set(newValue != syncedValue)
    }

    override var value: T
        get() = delegate.value
        set(newValue) {
            writeLock.withLock {
                markUserWrite(newValue)
                betweenMarkAndPublishForTest?.invoke()
                delegate.value = newValue
                persist(newValue)
            }
        }

    override fun compareAndSet(expect: T, update: T): Boolean {
        return writeLock.withLock {
            val c = delegate.compareAndSet(expect, update)
            if (c) {
                markUserWrite(update)
                persist(update)
            }
            c
        }
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

    /** Test-only: simulates a stale observer emission clobbering the value after the guard armed. */
    @PublishedApi internal fun simulateStaleClobberForTest(staleValue: T) {
        delegate.value = staleValue
    }

    /** Test-only hook, run under the write lock between mark and publish. Null in production. */
    @PublishedApi internal var betweenMarkAndPublishForTest: (() -> Unit)? = null

    /** Applies an observer emission without persisting; suppresses only the stale pre-write snapshot. */
    internal fun updateFromFlow(newValue: T) {
        writeLock.withLock {
            when {
                !awaitingWriteEcho.get() -> {
                    delegate.value = newValue
                    syncedValue = newValue
                }
                // distinctUntilChanged never re-emits an already-applied value, so the only
                // emission still equal to syncedValue is the racing pre-write snapshot.
                newValue == syncedValue -> { /* suppress */ }
                // The write's own echo, or an external change that arrived while waiting.
                // Reflect both: a lost echo would otherwise leave the guard armed forever.
                else -> {
                    delegate.value = newValue
                    awaitingWriteEcho.compareAndSet(true, false)
                    syncedValue = newValue
                }
            }
        }
    }

    /** Reverts the optimistic value after a failed persist; skipped when a newer write owns the state. */
    internal fun reconcileAfterFailedPersist(failedValue: T, durableValue: T) {
        writeLock.withLock {
            if (awaitingWriteEcho.get() && lastUserWrite == failedValue) {
                delegate.value = durableValue
                syncedValue = durableValue
                awaitingWriteEcho.set(false)
            }
        }
    }
}

@PublishedApi
internal class KSafeMutableStateFlowDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
    private val scope: CoroutineScope,
    private val mode: KSafeWriteMode,
) : ReadOnlyProperty<Any?, MutableStateFlow<T>> {
    // Build AND launch happen under the ref's lock: init starts an observer coroutine, so a
    // concurrent double-init would leak a second one.
    private val mutableStateFlow = KSafeLazyRef<KSafeMutableStateFlow<T>>()

    override fun getValue(thisRef: Any?, property: KProperty<*>): MutableStateFlow<T> =
        mutableStateFlow.getOrPut {
            val actualKey = key ?: property.name

            @Suppress("UNCHECKED_CAST")
            val initial = ksafe.core.getDirectRaw(actualKey, defaultValue, serializer) as T

            lateinit var msf: KSafeMutableStateFlow<T>
            msf = KSafeMutableStateFlow(initial) { newValue ->
                // Fallback is the last in-sync value, NOT defaultValue: on a locked device the
                // read returns the fallback verbatim, so the default would blank intact data.
                val reconcile: (Throwable) -> Unit = {
                    @Suppress("UNCHECKED_CAST")
                    val durable = ksafe.core.getDirectRaw(actualKey, msf.lastSyncedValue, serializer) as T
                    msf.reconcileAfterFailedPersist(newValue, durable)
                }
                try {
                    ksafe.core.putDirectRaw(actualKey, newValue, mode, serializer, onWriteFailed = reconcile)
                } catch (e: Throwable) {
                    // A throwing serializer fails before the core can report through onWriteFailed.
                    reconcile(e)
                    throw e
                }
            }

            // getFlowRaw retries transient decrypt failures internally, so a locked-device
            // emission can't kill observation.
            scope.launch {
                @Suppress("UNCHECKED_CAST")
                (ksafe.core.getFlowRaw(actualKey, defaultValue, serializer) as Flow<T>)
                    .collect { msf.updateFromFlow(it) }
            }

            msf
        }
}

/**
 * Delegate backed by a [MutableStateFlow] that persists every write; property name is the key
 * unless [key] is given, external changes are reflected in [scope], [mode] defaults to encrypted.
 */
inline fun <reified T> KSafe.asMutableStateFlow(
    defaultValue: T,
    scope: CoroutineScope,
    key: String? = null,
    mode: KSafeWriteMode = core.defaultEncryptedMode(),
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
    invoke(defaultValue, key, if (encrypted) core.defaultEncryptedMode() else KSafeWriteMode.Plain)
