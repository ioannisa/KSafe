package eu.anifantakis.lib.ksafe.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.SnapshotMutationPolicy
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.structuralEqualityPolicy
import kotlin.concurrent.Volatile
import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.properties.PropertyDelegateProvider
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/** Never matches an armed write, so a failure reported without a token claims nothing. */
private const val NO_WRITE_TOKEN = 0L

/**
 * A KSafe-persisted Compose [MutableState]: writes go through [valueSaver].
 * @param policy Gates recomposition and persistence; equivalent values are not persisted.
 */
@OptIn(ExperimentalAtomicApi::class)
class KSafeComposeState<T>(
    initialValue: T,
    private val valueSaver: (newValue: T) -> Unit,
    private val policy: SnapshotMutationPolicy<T>
) : MutableState<T>, ReadWriteProperty<Any?, T> {

    private var _internalState: MutableState<T> = mutableStateOf(initialValue, policy)

    // Identified by token, not value: two writes can carry equal values.
    private class UnresolvedWrite<T>(val value: T, val token: Long)

    private val writeTokens = AtomicLong(NO_WRITE_TOKEN)

    // The rollback's gate, not the write-echo latch below. Without external observation nothing
    // settles a write, so this holds the latest one until its failure or a superseding write.
    private val unresolvedWrite = AtomicReference<UnresolvedWrite<T>?>(null)

    /** Token of the write being saved; the saver captures it on the setter's own stack. */
    @PublishedApi internal fun writeTokenInFlight(): Long =
        unresolvedWrite.load()?.token ?: NO_WRITE_TOKEN

    /** Clears the slot only if [owner] still holds it, so a newer write keeps its rollback. */
    private fun settle(owner: UnresolvedWrite<T>?) {
        if (owner != null) unresolvedWrite.compareAndSet(owner, null)
    }

    // Latched while the latest write propagates to disk, so stale emissions cannot revert it.
    @Volatile
    private var awaitingWriteEcho = false

    // Last value known in sync with storage. Latched only while a write diverges from it: a write
    // netting back to this baseline produces no distinct echo.
    @Volatile
    private var syncedValue: T? = initialValue

    // Bumped per armed write so a stale timeout can never release a NEWER write's latch.
    @Volatile
    private var writeEchoGeneration = 0

    override var value: T
        get() {
            return _internalState.value
        }
        set(newValue) {
            val oldValueToCompare = _internalState.value
            if (!policy.equivalent(oldValueToCompare, newValue)) {
                // Arm before publishing, or a concurrent self-heal clobbers the write.
                unresolvedWrite.store(UnresolvedWrite(newValue, writeTokens.addAndFetch(1L)))
                @Suppress("UNCHECKED_CAST")
                awaitingWriteEcho = !policy.equivalent(newValue, syncedValue as T)
                if (awaitingWriteEcho) {
                    val gen = ++writeEchoGeneration
                    armWriteEchoTimeout(gen)
                }
                _internalState.value = newValue
                valueSaver(newValue)
            } else {
                _internalState.value = newValue
            }
        }

    /** Cold-start self-heal: applies a stored value without persisting, unless a write is unresolved. */
    @PublishedApi internal fun updateFromStorage(newValue: T) {
        if (awaitingWriteEcho || unresolvedWrite.load() != null) return
        betweenCheckAndPublishForTest?.invoke()
        _internalState.value = newValue
        // A write racing into this window owns the state; no later emission will fix a clobber.
        val raced = unresolvedWrite.load()
        if (raced != null) {
            _internalState.value = raced.value
        } else {
            syncedValue = newValue
        }
    }

    @PublishedApi internal var betweenCheckAndPublishForTest: (() -> Unit)? = null

    /** Applies a flow emission without persisting; only the stale pre-write snapshot is dropped. */
    @PublishedApi internal fun updateFromFlow(newValue: T) {
        val owner = unresolvedWrite.load()
        if (!awaitingWriteEcho) {
            _internalState.value = newValue
            syncedValue = newValue
            settle(owner)
            return
        }
        // The stale pre-write snapshot is the only emission that can revert the in-flight write:
        // distinctUntilChanged never re-emits an already-applied value.
        @Suppress("UNCHECKED_CAST")
        if (policy.equivalent(newValue, syncedValue as T)) return
        // Either the write's echo or an external change that landed first; applying it also
        // self-heals a stale clobber, since check-then-apply isn't atomic.
        _internalState.value = newValue
        awaitingWriteEcho = false
        syncedValue = newValue
        settle(owner)
    }

    // Null when nothing observes external changes, so a write outside observation gets no timeout.
    @Volatile
    private var writeEchoTimeoutScope: CoroutineScope? = null

    @Volatile
    private var writeEchoTimeoutMs: Long = WRITE_ECHO_TIMEOUT_MS

    /** Installs the scope and window backing the write-echo timeout, for the observation's life. */
    @PublishedApi internal fun attachWriteEchoTimeout(scope: CoroutineScope, timeoutMs: Long) {
        writeEchoTimeoutMs = timeoutMs
        writeEchoTimeoutScope = scope
        // Back-stop a write that armed before this scope existed, else a silent failure freezes it.
        if (awaitingWriteEcho) armWriteEchoTimeout(writeEchoGeneration)
    }

    @PublishedApi internal fun detachWriteEchoTimeout() {
        writeEchoTimeoutScope = null
    }

    // Releases the latch if no echo arrives: a persist can fail with no error, and storage then
    // never re-emits. The generation guard stops a stale timeout releasing a later write's latch.
    private fun armWriteEchoTimeout(generation: Int) {
        val scope = writeEchoTimeoutScope ?: return
        scope.launch {
            delay(writeEchoTimeoutMs)
            if (awaitingWriteEcho && writeEchoGeneration == generation) {
                awaitingWriteEcho = false
            }
        }
    }

    /**
     * Last value known in sync with storage — the fallback for a re-read that cannot resolve: a
     * strict entry on a locked device reads back as the caller's default.
     */
    @PublishedApi internal val lastSyncedValue: T
        @Suppress("UNCHECKED_CAST")
        get() = syncedValue as T

    /**
     * Reverts the optimistic value after its persist failed; storage never changed, so no echo
     * will correct it. Acts only on the write matched by [writeToken], claimed atomically.
     */
    @PublishedApi internal fun reconcileAfterFailedPersist(writeToken: Long, durableValue: T) {
        val owner = unresolvedWrite.load() ?: return
        if (owner.token != writeToken) return
        if (!unresolvedWrite.compareAndSet(owner, null)) return
        // Released before publishing, so a write arming after this line keeps its own latch.
        awaitingWriteEcho = false
        syncedValue = durableValue
        betweenGateAndPublishForTest?.invoke()
        _internalState.value = durableValue
        // A write that landed after the claim owns the state and must outlive this revert.
        unresolvedWrite.load()?.let { _internalState.value = it.value }
    }

    internal var betweenGateAndPublishForTest: (() -> Unit)? = null

    @PublishedApi internal fun simulateStaleClobberForTest(staleValue: T) {
        _internalState.value = staleValue
    }

    override fun getValue(thisRef: Any?, property: KProperty<*>): T {
        return value
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        this.value = value
    }

    override fun component1(): T = value
    override fun component2(): (T) -> Unit = { value = it }
}

/**
 * How long the cold-start self-heal waits for the first stored value — on WASM the initial
 * synchronous read returns the default while WebCrypto is still decrypting.
 */
@PublishedApi
internal const val SELF_HEAL_TIMEOUT_MS: Long = 5_000L

/** Backstop window for the write-echo latch when a write fails to persist without an error. */
@PublishedApi
internal const val WRITE_ECHO_TIMEOUT_MS: Long = 5_000L

/**
 * Observation lifecycle shared by [mutableStateOf] and [rememberKSafeState]: collects the flow
 * indefinitely when [observeExternalChanges], else a [coldStart] takes the first emission.
 */
@PublishedApi
internal suspend fun <T> KSafeComposeState<T>.observeFromStorage(
    flow: Flow<T>,
    coldStart: Boolean,
    observeExternalChanges: Boolean,
    selfHealTimeoutMs: Long = SELF_HEAL_TIMEOUT_MS,
    writeEchoTimeoutMs: Long = WRITE_ECHO_TIMEOUT_MS,
) {
    when {
        observeExternalChanges -> coroutineScope {
            attachWriteEchoTimeout(this, writeEchoTimeoutMs)
            try {
                flow.collect { updateFromFlow(it) }
            } finally {
                detachWriteEchoTimeout()
            }
        }
        coldStart -> withTimeoutOrNull(selfHealTimeoutMs) { flow.first() }
            ?.let { updateFromStorage(it) }
    }
}


/**
 * Creates a KSafe-persisted Compose [MutableState] using [structuralEqualityPolicy].
 * @param key Storage key; the property name when null.
 * @param mode Defaults to encrypted, inheriting `KSafeConfig.requireUnlockedDevice`.
 * @param scope When provided, external changes to the stored value propagate into the state.
 */
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = defaultWriteMode,
    scope: CoroutineScope? = null,
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    mutableStateOf(
        defaultValue = defaultValue,
        key = key,
        mode = mode,
        scope = scope,
        policy = structuralEqualityPolicy()
    )

/**
 * Creates a KSafe-persisted Compose [MutableState] for class/ViewModel properties: initialized
 * from storage when the delegate is created, changes persisted back. Not `remember`-wrapped —
 * use [rememberKSafeState] inside a `@Composable` body.
 * @param key Storage key; the property name when null.
 * @param mode Defaults to encrypted, inheriting `KSafeConfig.requireUnlockedDevice`.
 * @param scope When provided, external changes propagate into the state; null runs only the
 * cold-start self-heal.
 * @param policy Gates recomposition and persistence; equivalent values are not persisted.
 */
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = defaultWriteMode,
    scope: CoroutineScope? = null,
    policy: SnapshotMutationPolicy<T>
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> {
    val ksafe = this

    return PropertyDelegateProvider { _, property ->
        val actualKey = key ?: property.name

        val initialValue = ksafe.getDirect<T>(actualKey, defaultValue)

        // The saver only dereferences the state when a persist fails, long past initialization.
        lateinit var composeState: KSafeComposeState<T>
        val saver: (newValue: T) -> Unit = { newValueToSave ->
            // A persist can fail after this returns, so re-read the durable value and reconcile.
            val writeToken = composeState.writeTokenInFlight()
            val reconcile: (Throwable) -> Unit = { e ->
                println("KSafe: Failed to save value for key '$actualKey': ${e.message}")
                composeState.reconcileAfterFailedPersist(
                    writeToken,
                    // Last in-sync value, not defaultValue: the default would publish "empty"
                    // over a value that is intact on disk but unreadable right now.
                    ksafe.getDirect<T>(actualKey, composeState.lastSyncedValue),
                )
            }
            try {
                ksafe.putDirect<T>(actualKey, newValueToSave, mode, reconcile)
            } catch (e: Exception) {
                reconcile(e)
            }
        }

        composeState = KSafeComposeState(
            initialValue = initialValue,
            valueSaver = saver,
            policy = policy
        )

        val coldStart = (initialValue == defaultValue)
        if (scope != null || coldStart) {
            val healScope = scope ?: CoroutineScope(Dispatchers.Default)
            healScope.launch {
                composeState.observeFromStorage(
                    flow = ksafe.getFlow<T>(actualKey, defaultValue),
                    coldStart = coldStart,
                    observeExternalChanges = (scope != null),
                )
            }
        }

        composeState
    }
}

/** Use [mutableStateOf] with the [KSafeWriteMode] parameter instead. */
@Deprecated(
    "Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain",
    ReplaceWith("mutableStateOf(defaultValue, key, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)")
)
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    encrypted: Boolean
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    mutableStateOf(defaultValue, key, mode = if (encrypted) defaultWriteMode else KSafeWriteMode.Plain)

/** Use [mutableStateOf] with the [KSafeWriteMode] parameter instead. */
@Deprecated(
    "Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain",
    ReplaceWith("mutableStateOf(defaultValue, key, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain, policy)")
)
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    encrypted: Boolean,
    policy: SnapshotMutationPolicy<T>
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    mutableStateOf(defaultValue, key, mode = if (encrypted) defaultWriteMode else KSafeWriteMode.Plain, policy = policy)

/**
 * Composable-scoped persistent state — the `rememberSaveable` analogue for KSafe, surviving app
 * restarts. Use with `by` inside a `@Composable` body; leaving the composition cancels its
 * storage observation. Defaults to [KSafeWriteMode.Plain].
 * @param key Storage key; the property name when omitted.
 * @param observeExternalChanges When `true`, external writes to the key propagate into this
 *   state; `false` (default) runs only the cold-start self-heal.
 * @param policy Gates recomposition and persistence; equivalent values are not persisted.
 */
inline fun <reified T> KSafe.rememberKSafeState(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Plain,
    observeExternalChanges: Boolean = false,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): KSafeComposeStateProvider<T> {
    val ksafe = this
    return KSafeComposeStateProvider(
        explicitKey = key,
        defaultValue = defaultValue,
        observeExternalChanges = observeExternalChanges,
        policy = policy,
        // Memoization identity: the lambdas below bind this instance and mode, so a different
        // instance or mode must rebuild the state or reads/writes target the old store.
        instanceKey = ksafe,
        modeKey = mode,
        readInitial = { resolvedKey -> ksafe.getDirect<T>(resolvedKey, defaultValue) },
        readDurable = { resolvedKey, fallback -> ksafe.getDirect<T>(resolvedKey, fallback) },
        writeValue = { resolvedKey, newValue, onWriteFailed ->
            ksafe.putDirect<T>(resolvedKey, newValue, mode, onWriteFailed)
        },
        flowProvider = { resolvedKey -> ksafe.getFlow<T>(resolvedKey, defaultValue) },
    )
}

private fun <T> legacyReadDurable(
    readInitial: (String) -> T,
    policy: SnapshotMutationPolicy<T>,
    defaultValue: T,
): (String, T) -> T = { resolvedKey, fallback ->
    val durable = readInitial(resolvedKey)
    if (policy.equivalent(durable, defaultValue)) fallback else durable
}

/** Provider returned by [rememberKSafeState]; `provideDelegate` uses the property name as key. */
class KSafeComposeStateProvider<T> @PublishedApi internal constructor(
    private val explicitKey: String?,
    private val defaultValue: T,
    private val observeExternalChanges: Boolean,
    private val policy: SnapshotMutationPolicy<T>,
    private val instanceKey: Any?,
    private val modeKey: Any?,
    private val readInitial: (resolvedKey: String) -> T,
    private val readDurable: (resolvedKey: String, fallback: T) -> T,
    private val writeValue: (resolvedKey: String, newValue: T, onWriteFailed: (Throwable) -> Unit) -> Unit,
    private val flowProvider: (resolvedKey: String) -> Flow<T>,
) {
    /** Binary-compat entry for inlined callers that predate [readDurable]. */
    @PublishedApi internal constructor(
        explicitKey: String?,
        defaultValue: T,
        observeExternalChanges: Boolean,
        policy: SnapshotMutationPolicy<T>,
        instanceKey: Any?,
        modeKey: Any?,
        readInitial: (resolvedKey: String) -> T,
        writeValue: (resolvedKey: String, newValue: T, onWriteFailed: (Throwable) -> Unit) -> Unit,
        flowProvider: (resolvedKey: String) -> Flow<T>,
    ) : this(
        explicitKey, defaultValue, observeExternalChanges, policy, instanceKey, modeKey,
        readInitial, legacyReadDurable(readInitial, policy, defaultValue), writeValue, flowProvider,
    )

    /** Binary-compat entry for inlined callers that predate the failure-aware saver. */
    @PublishedApi internal constructor(
        explicitKey: String?,
        defaultValue: T,
        observeExternalChanges: Boolean,
        policy: SnapshotMutationPolicy<T>,
        instanceKey: Any?,
        modeKey: Any?,
        readInitial: (resolvedKey: String) -> T,
        writeValue: (resolvedKey: String, T) -> Unit,
        flowProvider: (resolvedKey: String) -> Flow<T>,
    ) : this(
        explicitKey, defaultValue, observeExternalChanges, policy, instanceKey, modeKey,
        readInitial, legacyReadDurable(readInitial, policy, defaultValue),
        { resolvedKey, newValue, _ -> writeValue(resolvedKey, newValue) }, flowProvider,
    )

    @Composable
    operator fun provideDelegate(
        thisRef: Any?,
        property: KProperty<*>,
    ): KSafeComposeState<T> {
        val key = explicitKey ?: property.name
        return rememberKSafeStateImpl(
            key = key,
            instanceKey = instanceKey,
            modeKey = modeKey,
            defaultValue = defaultValue,
            observeExternalChanges = observeExternalChanges,
            policy = policy,
            readInitial = { readInitial(key) },
            readDurable = { fallback -> readDurable(key, fallback) },
            writeValue = { newValue, onWriteFailed -> writeValue(key, newValue, onWriteFailed) },
            flowProvider = { flowProvider(key) },
        )
    }
}

@PublishedApi
@Composable
internal fun <T> rememberKSafeStateImpl(
    key: String,
    instanceKey: Any?,
    modeKey: Any?,
    defaultValue: T,
    observeExternalChanges: Boolean,
    policy: SnapshotMutationPolicy<T>,
    readInitial: () -> T,
    readDurable: (fallback: T) -> T,
    writeValue: (newValue: T, onWriteFailed: (Throwable) -> Unit) -> Unit,
    flowProvider: () -> Flow<T>,
): KSafeComposeState<T> {
    // Every parameter the state bakes in is a remember key, so a swap rebuilds it with
    // correctly-bound lambdas.
    val state = remember(key, instanceKey, modeKey, policy, defaultValue) {
        // The saver only dereferences the state when a persist fails, long past initialization.
        lateinit var s: KSafeComposeState<T>
        s = KSafeComposeState(
            initialValue = readInitial(),
            valueSaver = { newValue ->
                val writeToken = s.writeTokenInFlight()
                val reconcile: (Throwable) -> Unit = { e ->
                    println("KSafe: Failed to save value for key '$key': ${e.message}")
                    // Last in-sync value as the read's own fallback, so an unresolvable read
                    // yields it instead of the default.
                    s.reconcileAfterFailedPersist(writeToken, readDurable(s.lastSyncedValue))
                }
                try {
                    writeValue(newValue, reconcile)
                } catch (e: Exception) {
                    reconcile(e)
                }
            },
            policy = policy,
        )
        s
    }

    LaunchedEffect(key, instanceKey, modeKey, policy, defaultValue, observeExternalChanges) {
        state.observeFromStorage(
            flow = flowProvider(),
            coldStart = (state.value == defaultValue),
            observeExternalChanges = observeExternalChanges,
        )
    }

    return state
}
