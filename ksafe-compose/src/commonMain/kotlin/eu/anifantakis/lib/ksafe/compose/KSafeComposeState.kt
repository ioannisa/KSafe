package eu.anifantakis.lib.ksafe.compose

import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.SnapshotMutationPolicy
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.structuralEqualityPolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.drop
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
 * Creates a Jetpack Compose [MutableState] persisted by KSafe using default Compose equality.
 *
 * This is the simple overload. It uses [structuralEqualityPolicy], which is correct for most use
 * cases, and keeps call sites uncluttered.
 *
 * @param T The type of the state value.
 * @param defaultValue The default value if no value is found in KSafe.
 * @param key Optional explicit key for storing the value. If null, the property name is used.
 * @param mode Write mode. Defaults to encrypted/default.
 */
inline fun <reified T> KSafe.mutableStateOf(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted()
): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, T>> =
    mutableStateOf(
        defaultValue = defaultValue,
        key = key,
        mode = mode,
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

        // Self-heal: on platforms with async cache loading (WASM WebCrypto),
        // getDirect may return the default before decryption completes.
        // Observe getFlow for the first post-init emission and update reactively.
        if (initialValue == defaultValue) {
            CoroutineScope(Dispatchers.Default).launch {
                withTimeoutOrNull(5_000L) {
                    ksafe.getFlow<T>(actualKey, defaultValue)
                        .drop(1)    // skip current snapshot (same as getDirect result)
                        .first()    // wait for next emission (cache load)
                }?.let { composeState.updateFromStorage(it) }
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
    mutableStateOf(defaultValue, key, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)

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
    mutableStateOf(defaultValue, key, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain, policy)
