package eu.anifantakis.lib.ksafe.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.SnapshotMutationPolicy
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.structuralEqualityPolicy
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
    initialValue: T, // Value is pre-loaded by the composeStateOf provider
    private val valueSaver: (newValue: T) -> Unit, // Lambda to save the value, created by provider
    private val policy: SnapshotMutationPolicy<T>
) : MutableState<T>, ReadWriteProperty<Any?, T> {

    private var _internalState: MutableState<T> = mutableStateOf(initialValue, policy)
    private var userHasWritten = false

    override var value: T
        get() {
            return _internalState.value
        }
        set(newValue) {
            // We get the current value from the internal state for comparison
            val oldValueToCompare = _internalState.value
            _internalState.value = newValue // Update Compose state immediately

            // Persist only if the value has changed according to the policy
            if (!policy.equivalent(oldValueToCompare, newValue)) {
                userHasWritten = true
                valueSaver(newValue) // Call the provided saver lambda
            }
        }

    /**
     * Updates the state from storage without triggering persistence.
     * Used for async cache self-healing (e.g., WASM WebCrypto decryption completes
     * after initial synchronous read returned the default).
     * Skipped if the user has already written a value to avoid overwriting their change.
     */
    @PublishedApi internal fun updateFromStorage(newValue: T) {
        if (!userHasWritten) {
            _internalState.value = newValue
        }
    }

    /**
     * Updates the state from a flow emission without triggering persistence.
     * Used for continuous flow observation when a [CoroutineScope] is provided.
     * Always applies the update (even after user writes) because external changes
     * should be reflected regardless.
     */
    @PublishedApi internal fun updateFromFlow(newValue: T) {
        _internalState.value = newValue
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
 *  - `true` → indefinite [Flow.collect], every emission is propagated via
 *    [KSafeComposeState.updateFromFlow] (does not respect the user-write
 *    guard, so external writes always reflect).
 *  - `false` + [coldStart] → one-shot `flow.first()` with a [selfHealTimeoutMs]
 *    deadline, propagated via [KSafeComposeState.updateFromStorage] (respects
 *    the user-write guard so a pending self-heal cannot clobber a value the
 *    user has since set).
 *  - `false` + warm cache → returns immediately. No observation needed.
 *
 * Designed as a `suspend fun` so the caller picks the launching scope:
 *  - `mutableStateOf` (property-delegate path) launches it on the user-supplied
 *    `scope` when present, else on a detached fallback (preserves shipped behavior).
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
 * another screen or a background `put` call).
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
 * **Usage:**
 * ```kotlin
 * // In a Composable or ViewModel
 * var username by ksafe.mutableStateOf("Guest")
 * var counter by ksafe.mutableStateOf(0, key = "my_counter")
 * var settings by ksafe.mutableStateOf(Settings(), mode = KSafeWriteMode.Plain)
 * var secret by ksafe.mutableStateOf(
 *     "",
 *     mode = KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)
 * )
 * ```
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
 * another screen or a background `put` call). When null, only the WASM self-healing
 * one-shot observation is used.
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
            // (b): when the caller supplies `scope`, we honor it for both live
            // observation and the cold-start self-heal. The detached fallback
            // is reached only when no scope was provided AND the cache started
            // cold — i.e. the same set of cases as before the refactor.
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
    defaultValue: T,
    observeExternalChanges: Boolean,
    policy: SnapshotMutationPolicy<T>,
    readInitial: () -> T,
    writeValue: (T) -> Unit,
    flowProvider: () -> Flow<T>,
): KSafeComposeState<T> {
    val state = remember(key) {
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
    // composition cancels it; changing `key` or `observeExternalChanges`
    // cancels and re-launches.
    LaunchedEffect(key, observeExternalChanges) {
        state.observeFromStorage(
            flow = flowProvider(),
            coldStart = (state.value == defaultValue),
            observeExternalChanges = observeExternalChanges,
        )
    }

    return state
}
