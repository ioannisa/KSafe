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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.properties.PropertyDelegateProvider
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * A KSafe-persisted Compose [MutableState]: writes go through [valueSaver].
 *
 * @param policy Gates both recomposition and persistence — a value is persisted
 * only when `!policy.equivalent(oldValue, newValue)`.
 */
class KSafeComposeState<T>(
    initialValue: T,
    private val valueSaver: (newValue: T) -> Unit,
    private val policy: SnapshotMutationPolicy<T>
) : MutableState<T>, ReadWriteProperty<Any?, T> {

    private var _internalState: MutableState<T> = mutableStateOf(initialValue, policy)

    // Write-echo guard: latched while the user's latest write propagates to disk so
    // stale flow emissions cannot revert it; the live-observe path clears it once the
    // flow catches up. @Volatile: the self-heal coroutine races the setter's thread.
    @Volatile
    private var awaitingWriteEcho = false

    // The user's latest write, matched against emissions to detect the echo. Written
    // before the flag is raised so an observer that sees the flag also sees the value.
    @Volatile
    private var lastUserWrite: T? = null

    // Baseline last known in sync with storage. The guard is held only while the written
    // value diverges from it: a write netting back to the baseline never produces a
    // distinct echo, so latching on it would suppress external changes forever.
    @Volatile
    private var syncedValue: T? = initialValue

    override var value: T
        get() {
            return _internalState.value
        }
        set(newValue) {
            val oldValueToCompare = _internalState.value
            if (!policy.equivalent(oldValueToCompare, newValue)) {
                // Arm the guard before publishing: a concurrent one-shot self-heal either
                // sees the flag and skips, or catches it in its post-publish re-check.
                lastUserWrite = newValue
                // Latch only on genuine divergence from the synced baseline.
                @Suppress("UNCHECKED_CAST")
                awaitingWriteEcho = !policy.equivalent(newValue, syncedValue as T)
                _internalState.value = newValue
                valueSaver(newValue)
            } else {
                // Policy-equal: publish without persisting (Compose treats it as a no-op).
                _internalState.value = newValue
            }
        }

    /**
     * One-shot cold-start self-heal: applies a value read from storage without
     * persisting (e.g. async decryption finishing after the initial read returned
     * the default). Skipped once a user write is pending; never clears the guard.
     */
    @PublishedApi internal fun updateFromStorage(newValue: T) {
        if (!awaitingWriteEcho) {
            betweenCheckAndPublishForTest?.invoke()
            _internalState.value = newValue
            // Re-check after publishing: the setter arms the guard before it publishes, so
            // an armed flag here means a user write raced into this window — re-apply it
            // (this one-shot path has no later emission to correct a clobber).
            @Suppress("UNCHECKED_CAST")
            if (awaitingWriteEcho) {
                _internalState.value = lastUserWrite as T
            } else {
                syncedValue = newValue
            }
        }
    }

    /**
     * Test-only: runs between the guard check and the publish in [updateFromStorage],
     * letting tests race a user write into that window. Null in production.
     */
    @PublishedApi internal var betweenCheckAndPublishForTest: (() -> Unit)? = null

    /**
     * Applies a live flow emission without persisting. Suppressed while the user's own
     * write propagates to disk: the disk-derived flow lags an optimistic write, so an
     * older emission would revert the visible state. The latch clears once a
     * [policy]-equivalent echo arrives, and stays latched if no echo can ever match
     * (failed write, or a policy that never equates distinct instances).
     */
    @PublishedApi internal fun updateFromFlow(newValue: T) {
        if (!awaitingWriteEcho) {
            _internalState.value = newValue
            syncedValue = newValue
            return
        }
        @Suppress("UNCHECKED_CAST")
        if (policy.equivalent(newValue, lastUserWrite as T)) {
            // Echo of the user's own write: consume it and resume external reflection.
            // Re-apply the value — a stale emission that read the guard as clear may have
            // clobbered it after the setter published, and nothing else re-emits this
            // value (policy-equal in the non-raced case, so a Compose no-op).
            _internalState.value = newValue
            awaitingWriteEcho = false
            syncedValue = newValue
        }
    }

    /**
     * Test-only: simulates a stale observer emission clobbering the visible value after
     * the setter armed the guard, so tests can verify the echo self-heals it.
     */
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
 * How long the cold-start self-heal waits for `getFlow().first()` to deliver the
 * persisted value on platforms where the initial synchronous read can return the
 * default (e.g. WASM WebCrypto decrypting asynchronously).
 */
@PublishedApi
internal const val SELF_HEAL_TIMEOUT_MS: Long = 5_000L

/**
 * Observation lifecycle shared by [mutableStateOf] and [rememberKSafeState]: with
 * [observeExternalChanges] it collects the flow indefinitely via
 * [KSafeComposeState.updateFromFlow]; otherwise a [coldStart] takes the first
 * emission within [selfHealTimeoutMs] via [KSafeComposeState.updateFromStorage];
 * a warm start is a no-op. A `suspend fun` so the caller owns the scope
 * (user-supplied scope or a composition's `LaunchedEffect`).
 */
@PublishedApi
internal suspend fun <T> KSafeComposeState<T>.observeFromStorage(
    flow: Flow<T>,
    coldStart: Boolean,
    observeExternalChanges: Boolean,
    selfHealTimeoutMs: Long = SELF_HEAL_TIMEOUT_MS,
) {
    when {
        observeExternalChanges -> flow.collect { updateFromFlow(it) }
        coldStart -> withTimeoutOrNull(selfHealTimeoutMs) { flow.first() }
            ?.let { updateFromStorage(it) }
    }
}


/**
 * Creates a KSafe-persisted Compose [MutableState] using [structuralEqualityPolicy].
 *
 * @param key Storage key; the property name when null.
 * @param scope When provided, external changes to the stored value propagate into the
 * state; stale emissions are suppressed while this state's own write is in flight.
 */
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted(),
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
 * Creates a KSafe-persisted Compose [MutableState] for class/ViewModel properties:
 * initialized from storage when the delegate is created, changes persisted back.
 *
 * Do not call in a `@Composable` body — it is not `remember`-wrapped; use
 * [rememberKSafeState] there.
 *
 * @param key Storage key; the property name when null.
 * @param scope When provided, external changes to the stored value propagate into the
 * state; stale emissions are suppressed while this state's own write is in flight.
 * When null, only the one-shot cold-start self-heal runs.
 * @param policy Gates both recomposition and persistence: KSafe persists only when
 * `!policy.equivalent(old, new)`.
 */
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted(),
    scope: CoroutineScope? = null,
    policy: SnapshotMutationPolicy<T>
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> {
    val ksafe = this

    return PropertyDelegateProvider { _, property ->
        val actualKey = key ?: property.name

        val initialValue = ksafe.getDirect<T>(actualKey, defaultValue)

        val saver: (newValue: T) -> Unit = { newValueToSave ->
            try {
                ksafe.putDirect<T>(actualKey, newValueToSave, mode)
            } catch (e: Exception) {
                println("KSafe: Failed to save value for key '$actualKey': ${e.message}")
            }
        }

        val composeState = KSafeComposeState(
            initialValue = initialValue,
            valueSaver = saver,
            policy = policy
        )

        val coldStart = (initialValue == defaultValue)
        if (scope != null || coldStart) {
            // Detached fallback scope only when no scope was supplied and the cache started cold.
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

/**
 * @deprecated Use [mutableStateOf] with [KSafeWriteMode] parameter instead.
 */
@Deprecated(
    "Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain",
    ReplaceWith("mutableStateOf(defaultValue, key, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)")
)
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    encrypted: Boolean
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    mutableStateOf(defaultValue, key, mode = if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)

/**
 * @deprecated Use [mutableStateOf] with [KSafeWriteMode] parameter instead.
 */
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
    mutableStateOf(defaultValue, key, mode = if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain, policy = policy)

/**
 * Composable-scoped persistent state — the `rememberSaveable` analogue for KSafe,
 * surviving app restarts on every supported target.
 *
 * Use with `by` inside a `@Composable` body: the state is `remember`ed and its
 * storage observation runs in a [LaunchedEffect], so leaving the composition
 * cancels it. Defaults to [KSafeWriteMode.Plain] since Compose state is
 * typically UI ephemera.
 *
 * @param key Storage key; the property name when omitted.
 * @param observeExternalChanges When `true`, external writes to the key propagate
 *   into this state; stale emissions are suppressed while this state's own write
 *   is in flight. When `false` (default), only a one-shot cold-start self-heal runs.
 * @param policy Gates both recomposition and persistence: KSafe persists only
 *   when `!policy.equivalent(old, new)`.
 */
inline fun <reified T> KSafe.rememberKSafeState(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Plain,
    observeExternalChanges: Boolean = false,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): KSafeComposeStateProvider<T> {
    val ksafe = this
    // Reified-T resolution happens here so callers don't need to pass the
    // serializer. The provider captures lambdas that already know the type
    // tag; the actual key is resolved inside `provideDelegate` once we have
    // the property metadata.
    return KSafeComposeStateProvider(
        explicitKey = key,
        defaultValue = defaultValue,
        observeExternalChanges = observeExternalChanges,
        policy = policy,
        // Identity tokens for memoization: the captured lambdas below bind THIS
        // `ksafe` instance and `mode`, so re-invoking the composable with a
        // different instance or mode (e.g. a multi-account screen swapping
        // `KSafe(account.id)`, or toggling Plain↔Encrypted) must rebuild the
        // memoized state and observer — otherwise reads/writes keep targeting
        // the previous instance's store. The storage `key` alone does not
        // capture this; a stable singleton instance keeps the same identity,
        // so there is no rebuild churn.
        instanceKey = ksafe,
        modeKey = mode,
        readInitial = { resolvedKey -> ksafe.getDirect<T>(resolvedKey, defaultValue) },
        writeValue = { resolvedKey, newValue -> ksafe.putDirect<T>(resolvedKey, newValue, mode) },
        flowProvider = { resolvedKey -> ksafe.getFlow<T>(resolvedKey, defaultValue) },
    )
}

/**
 * Provider returned by [rememberKSafeState]. The `provideDelegate` operator is
 * `@Composable`, which is what lets the property name fall through to the
 * storage key when `by` is used inside a composable body.
 *
 * The class is public so it can appear in the inline factory's return type,
 * but the constructor is `@PublishedApi internal` — external code cannot
 * construct this directly; only the inline `rememberKSafeState` factory can.
 */
class KSafeComposeStateProvider<T> @PublishedApi internal constructor(
    private val explicitKey: String?,
    private val defaultValue: T,
    private val observeExternalChanges: Boolean,
    private val policy: SnapshotMutationPolicy<T>,
    private val instanceKey: Any?,
    private val modeKey: Any?,
    private val readInitial: (resolvedKey: String) -> T,
    private val writeValue: (resolvedKey: String, T) -> Unit,
    private val flowProvider: (resolvedKey: String) -> Flow<T>,
) {
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
            writeValue = { writeValue(key, it) },
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
    writeValue: (T) -> Unit,
    flowProvider: () -> Flow<T>,
): KSafeComposeState<T> {
    // Every parameter the memoized state bakes in participates in the keys:
    //  - `instanceKey`/`modeKey`: a swapped KSafe instance or write mode must
    //    rebuild the state with lambdas bound to the new instance;
    //  - `policy`: baked into the underlying `mutableStateOf(initial, policy)`
    //    and gates persistence — it can't be swapped on a live state, so it
    //    must rebuild; the standard policies are singletons, so no churn;
    //  - `defaultValue`: captured by readInitial/flowProvider — a changed
    //    default must re-resolve. Compared with equals(), the normal
    //    `remember`-key contract: pass a stable value.
    // A composable invoked with the same stable arguments never rebuilds.
    val state = remember(key, instanceKey, modeKey, policy, defaultValue) {
        KSafeComposeState(
            initialValue = readInitial(),
            valueSaver = { newValue ->
                try {
                    writeValue(newValue)
                } catch (e: Exception) {
                    println("KSafe: Failed to save value for key '$key': ${e.message}")
                }
            },
            policy = policy,
        )
    }

    // The LaunchedEffect coroutine is owned by the composition: leaving the
    // composition cancels it; changing any of the state's identity inputs or
    // `observeExternalChanges` cancels and re-launches so the observer follows
    // the rebuilt state.
    LaunchedEffect(key, instanceKey, modeKey, policy, defaultValue, observeExternalChanges) {
        state.observeFromStorage(
            flow = flowProvider(),
            coldStart = (state.value == defaultValue),
            observeExternalChanges = observeExternalChanges,
        )
    }

    return state
}
