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

/** Names no write, so a failure reported without one can never claim the visible value. */
private const val NO_WRITE_TOKEN = 0L

/**
 * A KSafe-persisted Compose [MutableState]: writes go through [valueSaver].
 *
 * @param policy Gates both recomposition and persistence — a value is persisted
 * only when `!policy.equivalent(oldValue, newValue)`.
 */
@OptIn(ExperimentalAtomicApi::class)
class KSafeComposeState<T>(
    initialValue: T,
    private val valueSaver: (newValue: T) -> Unit,
    private val policy: SnapshotMutationPolicy<T>
) : MutableState<T>, ReadWriteProperty<Any?, T> {

    private var _internalState: MutableState<T> = mutableStateOf(initialValue, policy)

    /**
     * A write in flight: the value it published, plus the token that names it. The token, not the
     * value — the policy decides only whether the setter fires, so two writes can carry equal
     * values and a value could then claim the wrong one.
     */
    private class UnresolvedWrite<T>(val value: T, val token: Long)

    private val writeTokens = AtomicLong(NO_WRITE_TOKEN)

    // The rollback's gate. Deliberately NOT the write-echo latch below: that one stays down for a
    // write netting back to the last synced value, and a timeout releases it mid-flight. Without
    // external observation nothing settles a write, so this holds the latest one for the state's
    // lifetime — by design; only its failure notification or a superseding write resolve it.
    private val unresolvedWrite = AtomicReference<UnresolvedWrite<T>?>(null)

    /**
     * The token of the write currently being saved, for the saver to capture: it runs on the
     * setter's own stack, before any later write can arm. A failure notification carrying it
     * then reverts that write and only that write.
     */
    @PublishedApi internal fun writeTokenInFlight(): Long =
        unresolvedWrite.load()?.token ?: NO_WRITE_TOKEN

    /**
     * Marks [owner] settled by storage. Conditional, so a write that arrived while a storage
     * value was being applied keeps the slot — and with it its own rollback.
     */
    private fun settle(owner: UnresolvedWrite<T>?) {
        if (owner != null) unresolvedWrite.compareAndSet(owner, null)
    }

    // Latched while the user's latest write propagates to disk so stale flow emissions
    // cannot revert it. @Volatile: the self-heal coroutine races the setter's thread.
    @Volatile
    private var awaitingWriteEcho = false

    // Last value known in sync with storage. Latch held only while the write diverges from it:
    // a write netting back to this baseline produces no distinct echo, so latching would
    // suppress external changes forever.
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
                // Arm before publishing: a concurrent self-heal either sees the flag and skips,
                // or catches it in its post-publish re-check.
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

    /**
     * One-shot cold-start self-heal: applies a value read from storage without persisting
     * (e.g. async decryption finishing after the initial read returned the default).
     * Skipped while any user write is unresolved; never clears the guard, never settles a write.
     * The write slot, not the latch, is the record: a write netting back to [syncedValue] leaves
     * the latch down while its value is still on its way to disk.
     */
    @PublishedApi internal fun updateFromStorage(newValue: T) {
        if (awaitingWriteEcho || unresolvedWrite.load() != null) return
        betweenCheckAndPublishForTest?.invoke()
        _internalState.value = newValue
        // A write racing into this window owns the state — re-apply it, since this one-shot
        // path has no later emission to correct a clobber.
        val raced = unresolvedWrite.load()
        if (raced != null) {
            _internalState.value = raced.value
        } else {
            syncedValue = newValue
        }
    }

    /**
     * Test-only: runs between the guard check and the publish in [updateFromStorage],
     * letting tests race a user write into that window. Null in production.
     */
    @PublishedApi internal var betweenCheckAndPublishForTest: (() -> Unit)? = null

    /**
     * Applies a live flow emission without persisting. While the user's own write is
     * propagating, only the stale pre-write snapshot ([syncedValue]) is suppressed; every
     * other emission — the write's own echo or a durable external change that won the race
     * to disk — is reflected and clears the latch, since the source flow never re-emits a
     * consumed value. The timeout in [armWriteEchoTimeout] remains the backstop for the
     * zero-emission case (a silently failed persist with no external traffic). Under a
     * policy that never equates distinct instances the pre-write snapshot briefly reverts
     * the write until its echo re-applies it — transient, unlike a latched freeze.
     */
    @PublishedApi internal fun updateFromFlow(newValue: T) {
        val owner = unresolvedWrite.load()
        if (!awaitingWriteEcho) {
            _internalState.value = newValue
            syncedValue = newValue
            settle(owner)
            return
        }
        // The stale pre-write snapshot is the ONLY value that can momentarily revert the
        // user's in-flight write. distinctUntilChanged never re-emits an already-applied
        // value, so the only emission still policy-equal to syncedValue is that racing
        // pre-write snapshot — suppress it and keep waiting.
        @Suppress("UNCHECKED_CAST")
        if (policy.equivalent(newValue, syncedValue as T)) return
        // Otherwise: the user-write echo, OR a genuine external change that arrived while
        // we waited. Matching only lastUserWrite here dropped a consumed external value for
        // good, freezing the state on the pre-write value until the timeout; applying also
        // self-heals a stale clobber of the user's own write (check-then-apply isn't atomic).
        _internalState.value = newValue
        awaitingWriteEcho = false
        syncedValue = newValue
        settle(owner)
    }

    // Owns the write-echo timeout coroutines, installed for the observation lifetime. Null when
    // nothing observes external changes (the only mode where the latch matters), so a write
    // outside observation schedules no timeout.
    @Volatile
    private var writeEchoTimeoutScope: CoroutineScope? = null

    @Volatile
    private var writeEchoTimeoutMs: Long = WRITE_ECHO_TIMEOUT_MS

    /**
     * Installs the [scope] and window used to backstop the write-echo latch, for the duration of
     * external observation. See [armWriteEchoTimeout].
     */
    @PublishedApi internal fun attachWriteEchoTimeout(scope: CoroutineScope, timeoutMs: Long) {
        writeEchoTimeoutMs = timeoutMs
        writeEchoTimeoutScope = scope
        // Back-stop a write that armed the latch before this scope existed (armWriteEchoTimeout
        // no-ops with no scope), else a silent persist failure freezes observation forever.
        if (awaitingWriteEcho) armWriteEchoTimeout(writeEchoGeneration)
    }

    @PublishedApi internal fun detachWriteEchoTimeout() {
        writeEchoTimeoutScope = null
    }

    /**
     * Bounded-timeout backstop for the write-echo latch. A write can fail to persist without a
     * synchronous error (strict Encrypted write failing later on a locked device, a rotation-outage
     * skip): storage never changes, `getFlow` never re-emits, and the latch would otherwise freeze
     * observation forever. This releases the latch if no echo arrives within the window; a
     * merely-slow echo still self-corrects via [updateFromFlow] once unlatched. Lives on the
     * observation scope; the [writeEchoGeneration] guard stops a stale timeout releasing a later
     * write's latch.
     */
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
     * The last value known to be in sync with storage — the state as it stood before the
     * current (failed) write. The correct fallback for a durable re-read that cannot resolve:
     * a strict entry on a locked device reads back as the CALLER'S DEFAULT, indistinguishable
     * from "no value", so reverting to the default would blank a value that is intact on disk.
     */
    @PublishedApi internal val lastSyncedValue: T
        @Suppress("UNCHECKED_CAST")
        get() = syncedValue as T

    /**
     * Reverts the optimistic value after its persist failed: the core rolled its caches back to
     * [durableValue] and storage never changed, so no echo will arrive to correct the phantom —
     * without this, the state (especially without external observation) keeps showing a value
     * that never reached disk.
     *
     * Applies only to the write that still owns the visible value, claimed atomically so two
     * failures — or a failure and the next write — cannot both act on it. A superseded write's
     * failure is a no-op: its successor's own echo or failure settles the state instead.
     * [writeToken] comes from [writeTokenInFlight], captured by the saver while the setter that
     * armed it is still on the stack; [NO_WRITE_TOKEN] never matches an armed write.
     *
     * Mirrors `KSafeMutableStateFlow.reconcileAfterFailedPersist`, which needs no such slot: it
     * always collects, so its latch is only ever down when storage has genuinely caught up.
     */
    @PublishedApi internal fun reconcileAfterFailedPersist(writeToken: Long, durableValue: T) {
        val owner = unresolvedWrite.load() ?: return
        if (owner.token != writeToken) return
        if (!unresolvedWrite.compareAndSet(owner, null)) return
        // Released before publishing, so a write that arms after this line keeps its own latch.
        // One arming just before it loses it — a stale emission could then flicker it until its
        // echo re-applies it, but never its value: the re-check below restores that.
        awaitingWriteEcho = false
        syncedValue = durableValue
        betweenGateAndPublishForTest?.invoke()
        _internalState.value = durableValue
        // A write that landed after the claim owns the state and must outlive this revert.
        unresolvedWrite.load()?.let { _internalState.value = it.value }
    }

    /**
     * Test-only: runs between the rollback's ownership decision and its publish, letting tests
     * race a newer user write into that window. Null in production.
     */
    internal var betweenGateAndPublishForTest: (() -> Unit)? = null

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
 * How long the cold-start self-heal waits for `getFlow().first()` on platforms where the initial
 * synchronous read can return the default (e.g. WASM WebCrypto decrypting asynchronously).
 */
@PublishedApi
internal const val SELF_HEAL_TIMEOUT_MS: Long = 5_000L

/**
 * Backstop window for the write-echo latch when a write fails to persist without a synchronous
 * error (so no echo ever arrives). Generous, so a merely-slow echo (async decrypt on WASM) clears
 * the latch normally first.
 */
@PublishedApi
internal const val WRITE_ECHO_TIMEOUT_MS: Long = 5_000L

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
 *
 * @param key Storage key; the property name when null.
 * @param mode Defaults to encrypted, inheriting the instance's
 * `KSafeConfig.requireUnlockedDevice` (same as [KSafe.putDirect]); pass an
 * explicit mode to override.
 * @param scope When provided, external changes to the stored value propagate into the
 * state; stale emissions are suppressed while this state's own write is in flight.
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
 * Creates a KSafe-persisted Compose [MutableState] for class/ViewModel properties:
 * initialized from storage when the delegate is created, changes persisted back.
 *
 * Do not call in a `@Composable` body — it is not `remember`-wrapped; use
 * [rememberKSafeState] there.
 *
 * @param key Storage key; the property name when null.
 * @param mode Defaults to encrypted, inheriting the instance's
 * `KSafeConfig.requireUnlockedDevice` (same as [KSafe.putDirect]); pass an
 * explicit mode to override.
 * @param scope When provided, external changes to the stored value propagate into the
 * state; stale emissions are suppressed while this state's own write is in flight.
 * When null, only the one-shot cold-start self-heal runs.
 * @param policy Gates both recomposition and persistence: KSafe persists only when
 * `!policy.equivalent(old, new)`.
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

        // The state is created after the saver but the saver only dereferences it when a
        // persist fails, long past initialization (same pattern as KSafeMutableStateFlow).
        lateinit var composeState: KSafeComposeState<T>
        val saver: (newValue: T) -> Unit = { newValueToSave ->
            // A persist can fail after this returns (async encrypt/commit): the core rolls its
            // caches back but the optimistic Compose value would keep showing the phantom, so
            // re-read the durable value and reconcile (never reverting a newer write).
            val writeToken = composeState.writeTokenInFlight()
            val reconcile: (Throwable) -> Unit = { e ->
                println("KSafe: Failed to save value for key '$actualKey': ${e.message}")
                composeState.reconcileAfterFailedPersist(
                    writeToken,
                    // Fallback is the last in-sync value, NOT defaultValue: a strict entry on a
                    // locked device cannot be decrypted and getDirect returns the fallback, so
                    // passing the default would publish "empty" over a value that is intact on
                    // disk — for a token that reads to the app as "logged out".
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
    mutableStateOf(defaultValue, key, mode = if (encrypted) defaultWriteMode else KSafeWriteMode.Plain)

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
    mutableStateOf(defaultValue, key, mode = if (encrypted) defaultWriteMode else KSafeWriteMode.Plain, policy = policy)

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
    return KSafeComposeStateProvider(
        explicitKey = key,
        defaultValue = defaultValue,
        observeExternalChanges = observeExternalChanges,
        policy = policy,
        // Identity tokens for memoization: the lambdas below bind THIS ksafe instance and mode,
        // so re-invoking with a different instance or mode (multi-account KSafe(account.id), or
        // Plain↔Encrypted) must rebuild the state, else reads/writes keep targeting the old store.
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

/**
 * Provider returned by [rememberKSafeState]. The `@Composable` `provideDelegate` operator lets the
 * property name fall through to the storage key when `by` is used inside a composable body.
 *
 * Public so it can appear in the inline factory's return type; the `@PublishedApi internal`
 * constructor keeps external code from constructing it directly.
 */
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
    /**
     * Binary-compat entry for consumers whose inlined `rememberKSafeState` predates [readDurable]:
     * their post-failure re-read keeps treating a value equal to the default as unresolvable.
     */
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

    /**
     * Binary-compat entry for consumers whose inlined `rememberKSafeState` predates the
     * failure-aware saver: their writes carry no async-failure notification, so a failed
     * persist keeps the pre-existing optimistic behavior (no rollback).
     */
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
    // Every parameter the memoized state bakes in participates in the remember keys, so a swapped
    // instance/mode/policy/default rebuilds the state with correctly-bound lambdas. Standard
    // policies are singletons and defaultValue is compared by equals(), so stable args never churn.
    val state = remember(key, instanceKey, modeKey, policy, defaultValue) {
        // Saver → state cycle: the saver only dereferences the state when a persist fails,
        // long past initialization (same pattern as KSafeMutableStateFlow).
        lateinit var s: KSafeComposeState<T>
        s = KSafeComposeState(
            initialValue = readInitial(),
            valueSaver = { newValue ->
                // A persist can fail after this returns (async encrypt/commit): the core rolls
                // its caches back but the optimistic Compose value would keep the phantom, so
                // reconcile the optimistic value away (never reverting a newer write).
                val writeToken = s.writeTokenInFlight()
                val reconcile: (Throwable) -> Unit = { e ->
                    println("KSafe: Failed to save value for key '$key': ${e.message}")
                    // Re-read with the last in-sync value as the read's OWN fallback: an unresolvable
                    // read yields it, while a stored value equal to the default comes back as itself.
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
