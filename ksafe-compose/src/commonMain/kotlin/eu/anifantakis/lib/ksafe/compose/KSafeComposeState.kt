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
 * A property delegate that manages a persisted mutable state for KSafe in Jetpack Compose.
 *
 * The initial value is loaded by the provider function. Subsequent changes
 * to the state are persisted back using a saver function provided by the delegate provider.
 *
 * @param T The type of the state value.
 * @param initialValue The value pre-loaded from KSafe by the delegate provider.
 * @param valueSaver A lambda function that takes the new value of type T and persists it.
 * @param policy The [SnapshotMutationPolicy] used by Compose to decide whether two values are equivalent.
 * KSafe uses the same policy gate before persisting:
 * persistence happens only when `!policy.equivalent(oldValue, newValue)`.
 */
class KSafeComposeState<T>(
    initialValue: T,
    private val valueSaver: (newValue: T) -> Unit,
    private val policy: SnapshotMutationPolicy<T>
) : MutableState<T>, ReadWriteProperty<Any?, T> {

    private var _internalState: MutableState<T> = mutableStateOf(initialValue, policy)

    // Latched while the user's latest write through this state is still
    // propagating to disk: stale flow emissions must not revert it. The
    // live-observe path clears it once the flow has caught up with the
    // written value, so external changes resume reflecting.
    //
    // @Volatile: the cold-start self-heal runs on a background coroutine while
    // the setter runs on the caller's thread — without it the heal could miss
    // the setter's write and overwrite the user's value with the persisted
    // default. (JVM/Native volatile; a no-op on single-threaded JS/Wasm.)
    @Volatile
    private var awaitingWriteEcho = false

    // The user's latest written value, compared against flow emissions to detect
    // the echo. Written BEFORE the flag is raised so a concurrent observer that
    // sees the flag also sees the fresh value.
    @Volatile
    private var lastUserWrite: T? = null

    // The value last known in sync with storage — what a stale/older emission carries.
    // The echo guard must be held ONLY while the written value diverges from this; a
    // write that nets back to it (an A→B→A toggle within one coalescing window) never
    // produces a distinct echo, so an unconditional latch would suppress external
    // observation forever (deep-review M2). Seeded from the initial value; updated
    // whenever an external emission or the echo brings the state back in sync.
    //
    // KNOWN LIMITATION (round-3 audit R7, accepted): if an intermediate value in an
    // A→B→A sequence reached disk in a SEPARATE batch, a stale snapshot of it can briefly
    // revert the state after the net-zero write clears the guard, until the follow-up
    // snapshot restores it — a self-correcting flicker, never data loss. Accepted because
    // the alternative (permanent latch) is the worse M2 bug; a full fix needs an
    // epoch-tagged observer. See KSafeMutableStateFlow in KSafeDelegate.kt for detail.
    @Volatile
    private var syncedValue: T? = initialValue

    override var value: T
        get() {
            return _internalState.value
        }
        set(newValue) {
            val oldValueToCompare = _internalState.value
            _internalState.value = newValue

            // Persist only if the value has changed according to the policy
            if (!policy.equivalent(oldValueToCompare, newValue)) {
                lastUserWrite = newValue
                @Suppress("UNCHECKED_CAST")
                // Guard only a genuine divergence from storage; a write that returns to
                // the synced value will never echo, so don't hold the latch for it.
                awaitingWriteEcho = !policy.equivalent(newValue, syncedValue as T)
                valueSaver(newValue)
            }
        }

    /**
     * Updates the state from storage without triggering persistence — the
     * one-shot cold-start self-heal path (e.g. WASM WebCrypto decryption
     * completing after the initial synchronous read returned the default).
     * Skipped if the user has already written a value; unlike the live-observe
     * path this never clears the guard, so a user write keeps it up for good.
     */
    @PublishedApi internal fun updateFromStorage(newValue: T) {
        if (!awaitingWriteEcho) {
            _internalState.value = newValue
            syncedValue = newValue
        }
    }

    /**
     * Updates the state from a live flow emission without triggering persistence.
     * Used for continuous flow observation when a [CoroutineScope] is provided.
     *
     * Suppressed while the user's own write is propagating to disk: the observed
     * flow is derived from disk snapshots and lags an optimistic write, so an
     * emission from before the commit carries an older value — applying it would
     * revert the visible state mid-gesture (in a `TextField`, dropping typed
     * characters).
     *
     * The suppression is precise, not permanent: once an emission
     * [policy]-equivalent to the user's last-written value arrives, the latch
     * clears and genuinely newer external changes reflect again. Conservatively,
     * the state keeps the user's value when no echo can ever match: a write
     * whose batch fails never echoes, and a policy that never equates distinct
     * instances (`neverEqualPolicy`, or `referentialEqualityPolicy` against a
     * deserialized round-trip) never matches — both keep suppression in place.
     */
    @PublishedApi internal fun updateFromFlow(newValue: T) {
        if (!awaitingWriteEcho) {
            _internalState.value = newValue
            syncedValue = newValue
            return
        }
        @Suppress("UNCHECKED_CAST")
        if (policy.equivalent(newValue, lastUserWrite as T)) {
            // The echo of the user's own write: consume it (the state already
            // shows this value) and resume external-change reflection.
            awaitingWriteEcho = false
            syncedValue = newValue
        }
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
 * Default timeout for the cold-start self-heal one-shot observation.
 *
 * On platforms with async cache loading (WASM WebCrypto), `getDirect` may
 * return the default before decryption completes. The self-heal observer
 * waits up to this duration for `getFlow().first()` to deliver the persisted
 * value, then calls [KSafeComposeState.updateFromStorage].
 */
@PublishedApi
internal const val SELF_HEAL_TIMEOUT_MS: Long = 5_000L

/**
 * Single source of truth for the persistent-state observation lifecycle.
 *
 * Two modes — selected by [observeExternalChanges]:
 *  - `true` → indefinite [Flow.collect], each emission propagated via
 *    [KSafeComposeState.updateFromFlow] (which respects the user-write guard:
 *    stale echoes are suppressed while the user's own write propagates, and
 *    reflection of external changes resumes once the flow catches up).
 *  - `false` + [coldStart] → one-shot `flow.first()` with a [selfHealTimeoutMs]
 *    deadline, propagated via [KSafeComposeState.updateFromStorage] (respects
 *    the user-write guard so a pending self-heal cannot clobber a value the
 *    user has since set).
 *  - `false` + warm cache → returns immediately. No observation needed.
 *
 * Designed as a `suspend fun` so the caller picks the launching scope:
 *  - `mutableStateOf` (property-delegate path) launches it on the user-supplied
 *    `scope` when present, else on a detached fallback.
 *  - `rememberKSafeState` runs it inside a `LaunchedEffect`, where the implicit
 *    coroutine is owned by the composition. Leaving the composition cancels
 *    the observation; changing `key` or `observeExternalChanges` cancels and
 *    re-launches automatically.
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
 * Creates a Jetpack Compose [MutableState] persisted by KSafe using default Compose equality.
 *
 * This is the simple overload. It uses [structuralEqualityPolicy], which is correct for most use
 * cases, and keeps call sites uncluttered.
 *
 * @param T The type of the state value.
 * @param defaultValue The default value if no value is found in KSafe.
 * @param key Optional explicit key for storing the value. If null, the property name is used.
 * @param mode Write mode. Defaults to encrypted/default.
 * @param scope Optional [CoroutineScope] for continuous flow observation. When provided,
 * the state automatically updates when the stored value changes externally (e.g., from
 * another screen or a background `put` call). While one of this state's own writes is
 * still propagating to disk, lagging emissions are suppressed (they would revert it);
 * external reflection resumes once the observed flow catches up with the written value.
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
 * Creates a Jetpack Compose [MutableState] that is persisted using KSafe.
 *
 * The state is initialized from KSafe when the delegate is created. Changes are
 * automatically persisted back. This function calls KSafe's `inline reified T`
 * [KSafe.getDirect] and [KSafe.putDirect] methods safely.
 *
 * **Usage — ViewModel / class properties only.** This delegate is created once
 * and lives for the owner's lifetime:
 * ```kotlin
 * class MyViewModel(ksafe: KSafe) : ViewModel() {
 *     var username by ksafe.mutableStateOf("Guest")
 *     var counter  by ksafe.mutableStateOf(0, key = "my_counter")
 *     var settings by ksafe.mutableStateOf(Settings(), mode = KSafeWriteMode.Plain)
 *     var secret   by ksafe.mutableStateOf(
 *         "",
 *         mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
 *     )
 * }
 * ```
 *
 * ⚠️ **Do not call this in a `@Composable` function body.** It is not
 * `remember`-wrapped, so each recomposition would re-create the state — re-reading
 * storage and discarding in-progress edits — and, on a cold-start key, launch a
 * background `CoroutineScope` not tied to the composition. For composable-body
 * state use [rememberKSafeState], which is `remember`-scoped and
 * `LaunchedEffect`-driven.
 *
 * **For biometric protection**, use [KSafe.verifyBiometric] or [KSafe.verifyBiometricDirect]
 * before modifying the value:
 * ```kotlin
 * ksafe.verifyBiometricDirect("Authenticate to save") { success ->
 *     if (success) {
 *         counter++
 *     }
 * }
 * ```
 *
 * @param T The type of the state value.
 * @param defaultValue The default value if no value is found in KSafe.
 * @param key Optional explicit key for storing the value. If null, the property name is used.
 * @param mode Write mode. Defaults to encrypted/default.
 * @param scope Optional [CoroutineScope] for continuous flow observation. When provided,
 * the state automatically updates when the stored value changes externally (e.g., from
 * another screen or a background `put` call). While one of this state's own writes is
 * still propagating to disk, lagging emissions are suppressed (they would revert it);
 * external reflection resumes once the observed flow catches up with the written value.
 * When null, only the WASM self-healing one-shot observation is used.
 * @param policy The [SnapshotMutationPolicy] for Compose state equality.
 * It affects both recomposition and persistence behavior.
 *
 * Common choices:
 * - [structuralEqualityPolicy] (default): treats values as unchanged when `old == new`.
 * - `referentialEqualityPolicy()`: treats values as unchanged only when `old === new`.
 * - `neverEqualPolicy()`: always treats assignment as a change.
 *
 * KSafe persists only when the policy says the value changed.
 * @return A [PropertyDelegateProvider] ensuring this is used with `by` delegation.
 */
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted(),
    scope: CoroutineScope? = null,
    policy: SnapshotMutationPolicy<T>
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> {
    // 'this' is the KSafe instance
    val ksafe = this

    return PropertyDelegateProvider { _, property ->
        val actualKey = key ?: property.name

        // Load initial value from storage
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
            // A caller-supplied scope is honored for both live observation and
            // the cold-start self-heal; the detached fallback is used only when
            // no scope was provided AND the cache started cold.
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

// ── Composable-scoped state ─────────────────────────────────────────────────

/**
 * Composable-scoped persistent state — the [androidx.compose.runtime.saveable.rememberSaveable]
 * analogue for KSafe.
 *
 * Returns a property-delegate provider that, when used with `by` inside a
 * `@Composable` function body, materialises a [MutableState] backed by KSafe
 * storage. The state survives recomposition via [remember] and is tied to the
 * composition's lifecycle. Reads and writes complete synchronously through
 * KSafe's hot cache; the underlying disk write is coalesced and batched.
 *
 * ## API shape
 * The factory itself is **not** `@Composable` — it just builds a provider.
 * The provider's `provideDelegate` IS `@Composable`, which is why this
 * function must be used with `by` inside a composable body, and why the
 * property name can be reflected as the storage key when [key] is omitted
 * (mirroring [mutableStateOf]).
 *
 * ## Differences from the [mutableStateOf] property delegate
 *  - **Composable-scoped lifetime.** Self-heal and (optional) live observation
 *    run on the [LaunchedEffect] coroutine, so leaving the composition cancels
 *    them automatically. No detached coroutines are spawned, which makes this
 *    helper safe to call at recomposition rate.
 *  - **Plain by default.** Compose state is typically UI ephemera (selected
 *    tab, scroll position) where encryption is overkill. Pass
 *    `mode = KSafeWriteMode.Encrypted(...)` to opt in.
 *
 * ## vs. `rememberSaveable`
 *  - `rememberSaveable` survives configuration changes and (via the saveable
 *    state registry) process death for [Bundle][android.os.Bundle]-friendly
 *    types on Android. State is cleared on cold app launch.
 *  - `rememberKSafeState` survives **app restarts**, on every supported target
 *    (Android, iOS, JVM, Web), with optional encryption.
 *
 * ## Example
 * ```kotlin
 * @Composable
 * fun TabbedScreen(ksafe: KSafe) {
 *     // Auto-key — storage key resolves to the property name "currentTab".
 *     var currentTab by ksafe.rememberKSafeState(Tab.Home)
 *
 *     // Explicit key — useful for namespaced or non-property-name keys.
 *     var draft by ksafe.rememberKSafeState("", key = "screen.draft")
 * }
 * ```
 *
 * @param defaultValue Returned when the key is absent at first composition.
 * @param key Storage key. Optional — when omitted the property name from the
 *   `by` declaration is used (matching [mutableStateOf]).
 * @param mode Write mode. Defaults to [KSafeWriteMode.Plain].
 * @param observeExternalChanges When `true`, external writes to the key (from
 *   another screen, ViewModel, or KSafe instance) propagate into this state.
 *   While one of this state's own writes is still propagating to disk, lagging
 *   emissions are suppressed (they would revert it); external reflection
 *   resumes once the observed flow catches up with the written value.
 *   When `false` (default), only a one-shot cold-start self-heal runs.
 * @param policy Snapshot mutation policy. Affects both recomposition and
 *   persistence — KSafe persists only when `!policy.equivalent(old, new)`.
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
