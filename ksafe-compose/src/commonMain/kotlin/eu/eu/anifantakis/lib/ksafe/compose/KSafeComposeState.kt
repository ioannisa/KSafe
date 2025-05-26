package eu.eu.anifantakis.lib.ksafe.compose

import eu.anifantakis.lib.ksafe.KSafe
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.SnapshotMutationPolicy
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.structuralEqualityPolicy
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
 * @param policy The [SnapshotMutationPolicy] to use for the [MutableState].
 */
class KSafeComposeState<T>(
    initialValue: T, // Value is pre-loaded by the composeStateOf provider
    private val valueSaver: (newValue: T) -> Unit, // Lambda to save the value, created by provider
    private val policy: SnapshotMutationPolicy<T>
) : MutableState<T>, ReadWriteProperty<Any?, T> {

    // No longer needs: KSafe, defaultValue, explicitKey, encrypted for its own ops.
    // No longer needs: propertyName, _isInitialized (for lazy loading), actualKey, loadPersistedValueAndUpdateState.
    // The atomicfu for _isInitialized is also not needed here as loading is eager in the provider.

    private var _internalState: MutableState<T> = mutableStateOf(initialValue, policy)

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
                valueSaver(newValue) // Call the provided saver lambda
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
 * Creates a Jetpack Compose [MutableState] that is persisted using KSafe.
 *
 * The state is initialized from KSafe when the delegate is created. Changes are
 * automatically persisted back. This function calls KSafe's `inline reified T`
 * `getDirect` and `putDirect` methods safely.
 *
 * @param T The type of the state value.
 * @param defaultValue The default value if no value is found in KSafe.
 * @param key Optional explicit key for storing the value. If null, the property name is used.
 * @param encrypted Whether the value should be encrypted (defaults to true).
 * @param policy The [SnapshotMutationPolicy] for the [MutableState] (defaults to [structuralEqualityPolicy]).
 * @return A [PropertyDelegateProvider] ensuring this is used with `by` delegation.
 */
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    encrypted: Boolean = true,
    policy: SnapshotMutationPolicy<T> = structuralEqualityPolicy()
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> {
    // 'this' is the KSafe instance
    val ksafe = this

    return PropertyDelegateProvider { _, property ->
        val actualKey = key ?: property.name
        val initialValue = ksafe.getDirect<T>(actualKey, defaultValue, encrypted)

        val saver: (newValue: T) -> Unit = { newValueToSave ->
            ksafe.putDirect<T>(actualKey, newValueToSave, encrypted)
        }

        KSafeComposeState(
            initialValue = initialValue,
            valueSaver = saver,
            policy = policy
        )
    }
}