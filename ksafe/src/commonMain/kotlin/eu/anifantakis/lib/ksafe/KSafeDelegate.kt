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

/**
 * Superseded by [KSafeReference], kept only so call sites inlined against ≤3.1.0
 * keep linking. New code never instantiates it.
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
 * Allows KSafe to be used with property delegation — and, since the result is a
 * [KSafeReference], held directly in a `val` for no-`by` access via
 * [KSafeReference.value] (an explicit [key] required for that; see [KSafeReference]).
 *
 * Uses non-blocking [KSafe.getDirect]/[KSafe.putDirect] under the hood.
 * Default mode is encrypted, inheriting the instance's `KSafeConfig.requireUnlockedDevice`
 * (same as [KSafe.putDirect]); pass an explicit [mode] to override.
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
    // stateIn(Eagerly) launches a sharing coroutine, so a concurrent double-init would leak one.
    private val stateFlow = KSafeLazyRef<StateFlow<T>>()

    override fun getValue(thisRef: Any?, property: KProperty<*>): StateFlow<T> = stateFlow.getOrPut {
        ksafe.getStateFlowRaw(key ?: property.name, defaultValue, serializer, scope)
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

/**
 * A cold [Flow] you can also write to, returned by [KSafe.asWritableFlow]:
 * collection observes persisted changes; [set] persists via [KSafe.putDirect].
 * No synchronous getter by design — a sync read against a cold web cache would
 * return the default instead of the persisted value.
 */
class WritableKSafeFlow<T> @PublishedApi internal constructor(
    private val source: Flow<T>,
    private val writer: (T) -> Unit,
) : Flow<T> by source {
    /** Persists [value] with the originating call's [KSafeWriteMode]; collectors see it on the next emission. */
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
 * Property delegate backed by a [WritableKSafeFlow] — a [Flow] you can also
 * [WritableKSafeFlow.set]. Uses the property name as key unless [key] is given.
 * No [CoroutineScope] needed: the flow is cold and writes are fire-and-forget.
 * Default [mode] is encrypted, inheriting the instance's `KSafeConfig.requireUnlockedDevice`.
 * On Web, only writes made through this same [KSafe] instance are observed (see [KSafe.getFlow]).
 */
inline fun <reified T> KSafe.asWritableFlow(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = core.defaultEncryptedMode(),
): ReadOnlyProperty<Any?, WritableKSafeFlow<T>> =
    KSafeWritableFlowDelegate(this, serializer(), defaultValue, key, mode)

/**
 * Property delegate backed by [KSafe.getStateFlow]. Uses the property name as
 * key unless [key] is given. The initial value is resolved synchronously via
 * [KSafe.getDirect], preventing a brief incorrect emission of the default.
 */
inline fun <reified T> KSafe.asStateFlow(
    defaultValue: T,
    scope: CoroutineScope,
    key: String? = null,
): ReadOnlyProperty<Any?, StateFlow<T>> = KSafeStateFlowDelegate(this, serializer(), defaultValue, key, scope)

/**
 * A [MutableStateFlow] that persists every write to KSafe via [KSafe.putDirect]
 * and reflects external changes via flow observation in the provided [CoroutineScope].
 * While one of your own writes is still propagating to disk, lagging disk emissions
 * are suppressed so they can't momentarily revert it; external reflection resumes
 * once the observed flow catches up with the written value. A write whose persist
 * fails is reverted to the durable value (see [reconcileAfterFailedPersist]).
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

    // Serializes echo bookkeeping (lastUserWrite, syncedValue, awaitingWriteEcho)
    // so concurrent writers never see a half-updated tuple.
    // persist() also runs INSIDE the lock: it only enqueues (a synchronous cache
    // mutation plus a trySend to an unlimited channel — no I/O, no suspension),
    // and enqueuing outside let two racing writers publish A→B but enqueue B→A,
    // making the durable final value the one the visible ordering had discarded.
    private val writeLock = KSafeInitLock()

    // Latched while the user's latest write is propagating, so stale disk echoes
    // can't revert it. Cleared by [updateFromFlow] once the flow catches up.
    private val awaitingWriteEcho = KSafeAtomicFlag(false)

    // The user's latest written value, compared against observer emissions to
    // detect the echo. Written BEFORE the flag is raised so a concurrent
    // [updateFromFlow] that observes the flag also observes the fresh value.
    @kotlin.concurrent.Volatile
    private var lastUserWrite: T? = null

    // Value last known in sync with storage. The guard is raised only while the
    // written value differs from this, so a net-zero write (A→B→A) that produces
    // no distinct echo doesn't suppress external observation permanently.
    // Trade-off: an intermediate B that reached disk separately can transiently
    // revert a net-zero write until the follow-up snapshot restores it — a brief
    // self-correcting flicker, never data loss.
    // Seeded with the initial value, which the delegate read from storage.
    @kotlin.concurrent.Volatile
    private var syncedValue: T = initialValue

    /**
     * The value last known in sync with storage. The correct fallback for a durable re-read
     * that cannot resolve: a strict entry on a locked device reads back as the CALLER'S
     * DEFAULT, indistinguishable from "no value", so reverting to the default would blank a
     * value that is intact on disk.
     */
    internal val lastSyncedValue: T get() = syncedValue

    /** Raise the echo guard only for a write that diverges from storage. */
    private fun markUserWrite(newValue: T) {
        lastUserWrite = newValue
        // No net divergence → nothing to echo, nothing to protect: clear the guard.
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

    /** Test-only: simulates a stale observer emission clobbering the visible value after the guard armed, to verify the self-heal in [updateFromFlow]. */
    @PublishedApi internal fun simulateStaleClobberForTest(staleValue: T) {
        delegate.value = staleValue
    }

    /** Test-only hook run inside the write lock, after markUserWrite and before the delegate.value publish, to verify a concurrent writer is serialized. Null in production. */
    @PublishedApi internal var betweenMarkAndPublishForTest: (() -> Unit)? = null

    /**
     * Applies an observer-flow emission without persisting. While the user's own write
     * is propagating, only the stale pre-write snapshot ([syncedValue]) is suppressed;
     * every other emission — the write's own echo or a genuine external change — is
     * reflected and clears the latch, so an echo lost to a failed or conflated persist
     * can't leave this flow permanently deaf to later external updates. Runs under
     * [writeLock].
     */
    internal fun updateFromFlow(newValue: T) {
        writeLock.withLock {
            when {
                // Guard down: reflect external snapshots freely.
                !awaitingWriteEcho.get() -> {
                    delegate.value = newValue
                    syncedValue = newValue
                }
                // The stale pre-write snapshot is the ONLY value that can momentarily
                // revert the user's in-flight write. distinctUntilChanged never re-emits
                // an already-applied value, so the only emission still equal to syncedValue
                // is that racing pre-write snapshot — suppress it and keep waiting.
                newValue == syncedValue -> { /* stale pre-write snapshot: suppress */ }
                // Otherwise: the user-write echo, OR a genuine external change that arrived
                // while we waited (the echo was lost to a failed/conflated persist). Matching
                // only lastUserWrite here left the guard armed forever when the echo never
                // came, going deaf to every later external snapshot; reflecting also self-heals
                // a stale clobber of the user's own write (the setter/guard check isn't atomic).
                else -> {
                    delegate.value = newValue
                    awaitingWriteEcho.compareAndSet(true, false)
                    syncedValue = newValue
                }
            }
        }
    }

    /**
     * Reverts the optimistic value after its fire-and-forget persist failed: the core rolled
     * its caches back to [durableValue], but storage never changed, so no echo will arrive
     * and a re-emission of the durable value is either impossible (distinctUntilChanged) or
     * suppressed as the pre-write snapshot — without this, the phantom (and the armed latch)
     * outlives the failure until a different-valued durable write. Skipped when a newer user
     * write owns the state ([lastUserWrite] no longer equals [failedValue]); that write's own
     * echo — or its own failure callback — settles the flow instead.
     */
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
    // Initialization launches an observer coroutine, so a concurrent double-init would leak a
    // second observer — the build AND the launch happen under the ref's lock.
    private val mutableStateFlow = KSafeLazyRef<KSafeMutableStateFlow<T>>()

    override fun getValue(thisRef: Any?, property: KProperty<*>): MutableStateFlow<T> =
        mutableStateFlow.getOrPut {
            val actualKey = key ?: property.name

            @Suppress("UNCHECKED_CAST")
            val initial = ksafe.core.getDirectRaw(actualKey, defaultValue, serializer) as T

            lateinit var msf: KSafeMutableStateFlow<T>
            msf = KSafeMutableStateFlow(initial) { newValue ->
                ksafe.core.putDirectRaw(actualKey, newValue, mode, serializer, onWriteFailed = {
                    // The write never became durable and the core already rolled back, so no
                    // echo is coming — re-read the durable value and reconcile. The fallback is
                    // the last in-sync value, NOT defaultValue: on a locked device the entry
                    // cannot be decrypted and the read returns the fallback verbatim, so the
                    // default would publish "empty" over a value that is intact on disk.
                    @Suppress("UNCHECKED_CAST")
                    val durable = ksafe.core.getDirectRaw(actualKey, msf.lastSyncedValue, serializer) as T
                    msf.reconcileAfterFailedPersist(newValue, durable)
                })
            }

            // getFlowRaw retries transient decrypt failures internally, so a locked-device
            // emission can't crash [scope] or kill observation.
            scope.launch {
                @Suppress("UNCHECKED_CAST")
                (ksafe.core.getFlowRaw(actualKey, defaultValue, serializer) as Flow<T>)
                    .collect { msf.updateFromFlow(it) }
            }

            msf
        }
}

/**
 * Property delegate backed by a [MutableStateFlow] that persists every write to
 * KSafe. Uses the property name as key unless [key] is given; external changes
 * are reflected via flow observation in [scope]. Writes use the specified [mode],
 * defaulting to encrypted with the instance's `KSafeConfig.requireUnlockedDevice`.
 * On Web, only writes made through this same [KSafe] instance are observed (see [KSafe.getFlow]).
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
