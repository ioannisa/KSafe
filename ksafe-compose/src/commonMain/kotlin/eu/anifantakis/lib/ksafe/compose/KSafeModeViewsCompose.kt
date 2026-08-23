package eu.anifantakis.lib.ksafe.compose

import androidx.compose.runtime.SnapshotMutationPolicy
import androidx.compose.runtime.structuralEqualityPolicy
import eu.anifantakis.lib.ksafe.KSafeEncrypted
import eu.anifantakis.lib.ksafe.KSafeHardwareIsolated
import eu.anifantakis.lib.ksafe.KSafePlain
import kotlin.properties.PropertyDelegateProvider
import kotlin.properties.ReadWriteProperty
import kotlinx.coroutines.CoroutineScope

// Compose factories for the write-mode views (KSafePlain / KSafeEncrypted /
// KSafeHardwareIsolated): the same `mutableStateOf` / `rememberKSafeState` surface as on
// KSafe, minus the `mode` parameter — the view's frozen mode is the mode. Without these,
// a Compose app would fall back to the raw KSafe exactly where most writes happen, and
// the type guarantee would have a hole.

/**
 * Persisted Compose state on a [KSafePlain] view — writes are always plain.
 * Same behavior as [KSafe.mutableStateOf] with `mode = KSafeWriteMode.Plain`.
 */
inline fun <reified T> KSafePlain.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    scope: CoroutineScope? = null,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    ksafe.mutableStateOf(defaultValue, key, mode, scope, policy)

/**
 * Persisted Compose state on a [KSafeEncrypted] view — writes always use the view's
 * frozen encrypted mode. Same behavior as [KSafe.mutableStateOf] with that mode.
 */
inline fun <reified T> KSafeEncrypted.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    scope: CoroutineScope? = null,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    ksafe.mutableStateOf(defaultValue, key, mode, scope, policy)

/**
 * Persisted Compose state on a [KSafeHardwareIsolated] view — writes always request
 * hardware isolation via the view's frozen mode. Same behavior as [KSafe.mutableStateOf]
 * with that mode.
 */
inline fun <reified T> KSafeHardwareIsolated.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    scope: CoroutineScope? = null,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    ksafe.mutableStateOf(defaultValue, key, mode, scope, policy)

/**
 * Composable-local persisted state on a [KSafePlain] view. Matches the stock
 * [KSafe.rememberKSafeState] default (`Plain` — UI ephemera), here as a type guarantee.
 */
inline fun <reified T> KSafePlain.rememberKSafeState(
    defaultValue: T,
    key: String? = null,
    observeExternalChanges: Boolean = false,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): KSafeComposeStateProvider<T> =
    ksafe.rememberKSafeState(defaultValue, key, mode, observeExternalChanges, policy)

/**
 * Composable-local persisted state on a [KSafeEncrypted] view. Note the semantic shift
 * from the stock API: [KSafe.rememberKSafeState] defaults to `Plain`; through this view
 * every write is encrypted with the frozen mode — which is the point of the type.
 */
inline fun <reified T> KSafeEncrypted.rememberKSafeState(
    defaultValue: T,
    key: String? = null,
    observeExternalChanges: Boolean = false,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): KSafeComposeStateProvider<T> =
    ksafe.rememberKSafeState(defaultValue, key, mode, observeExternalChanges, policy)

/**
 * Composable-local persisted state on a [KSafeHardwareIsolated] view. Note the semantic
 * shift from the stock API: [KSafe.rememberKSafeState] defaults to `Plain`; through this
 * view every write requests hardware isolation via the frozen mode.
 */
inline fun <reified T> KSafeHardwareIsolated.rememberKSafeState(
    defaultValue: T,
    key: String? = null,
    observeExternalChanges: Boolean = false,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): KSafeComposeStateProvider<T> =
    ksafe.rememberKSafeState(defaultValue, key, mode, observeExternalChanges, policy)
