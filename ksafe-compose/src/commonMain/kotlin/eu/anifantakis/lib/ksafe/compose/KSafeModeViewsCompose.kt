package eu.anifantakis.lib.ksafe.compose

import androidx.compose.runtime.SnapshotMutationPolicy
import androidx.compose.runtime.structuralEqualityPolicy
import eu.anifantakis.lib.ksafe.KSafeEncrypted
import eu.anifantakis.lib.ksafe.KSafeHardwareIsolated
import eu.anifantakis.lib.ksafe.KSafePlain
import kotlin.properties.PropertyDelegateProvider
import kotlin.properties.ReadWriteProperty
import kotlinx.coroutines.CoroutineScope

// Compose factories for the write-mode views: the same surface as on KSafe, minus the `mode`
// parameter — the view's frozen mode is the mode.

/**
 * Persisted Compose state on a [KSafePlain] view — writes are always plain. Same parameters as
 * the `KSafe.mutableStateOf` base minus `mode`: [key] defaults to the property name, [scope]
 * makes external writes to the key propagate into the state.
 */
inline fun <reified T> KSafePlain.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    scope: CoroutineScope? = null,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    ksafe.mutableStateOf(defaultValue, key, mode, scope, policy)

/**
 * Persisted Compose state on a [KSafeEncrypted] view — writes use the view's frozen mode. Same
 * parameters as the `KSafe.mutableStateOf` base minus `mode`: [key] defaults to the property
 * name, [scope] makes external writes to the key propagate into the state.
 */
inline fun <reified T> KSafeEncrypted.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    scope: CoroutineScope? = null,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    ksafe.mutableStateOf(defaultValue, key, mode, scope, policy)

/**
 * Persisted Compose state on a [KSafeHardwareIsolated] view — writes request hardware isolation.
 * Same parameters as the `KSafe.mutableStateOf` base minus `mode`: [key] defaults to the
 * property name, [scope] makes external writes to the key propagate into the state.
 */
inline fun <reified T> KSafeHardwareIsolated.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    scope: CoroutineScope? = null,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    ksafe.mutableStateOf(defaultValue, key, mode, scope, policy)

/**
 * Composable-local persisted state on a [KSafePlain] view. Same parameters as the
 * `KSafe.rememberKSafeState` base minus `mode`: [key] defaults to the property name,
 * [observeExternalChanges] makes external writes to the key propagate into the state.
 */
inline fun <reified T> KSafePlain.rememberKSafeState(
    defaultValue: T,
    key: String? = null,
    observeExternalChanges: Boolean = false,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): KSafeComposeStateProvider<T> =
    ksafe.rememberKSafeState(defaultValue, key, mode, observeExternalChanges, policy)

/**
 * Composable-local persisted state on a [KSafeEncrypted] view — encrypted, unlike the `Plain`
 * default of the `KSafe.rememberKSafeState` base, whose other parameters it shares: [key]
 * defaults to the property name, [observeExternalChanges] makes external writes propagate in.
 */
inline fun <reified T> KSafeEncrypted.rememberKSafeState(
    defaultValue: T,
    key: String? = null,
    observeExternalChanges: Boolean = false,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): KSafeComposeStateProvider<T> =
    ksafe.rememberKSafeState(defaultValue, key, mode, observeExternalChanges, policy)

/**
 * Composable-local persisted state on a [KSafeHardwareIsolated] view — hardware-isolated, unlike
 * the `Plain` default of the `KSafe.rememberKSafeState` base, whose other parameters it shares:
 * [key] defaults to the property name, [observeExternalChanges] makes external writes propagate in.
 */
inline fun <reified T> KSafeHardwareIsolated.rememberKSafeState(
    defaultValue: T,
    key: String? = null,
    observeExternalChanges: Boolean = false,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy(),
): KSafeComposeStateProvider<T> =
    ksafe.rememberKSafeState(defaultValue, key, mode, observeExternalChanges, policy)
