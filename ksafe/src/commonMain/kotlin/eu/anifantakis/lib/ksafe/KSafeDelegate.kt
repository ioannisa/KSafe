package eu.anifantakis.lib.ksafe

import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * Allows KSafe to be used with property delegation.
 *
 * This delegate uses the non-blocking [KSafe.getDirect] and [KSafe.putDirect] APIs internally.
 * This ensures that accessing delegated properties on the Main Thread is safe and will not cause UI freezes.
 *
 * **Usage:**
 * ```kotlin
 * val ksafe: KSafe = // ... obtain instance
 *
 * // Property name "mySetting" is used as the key
 * var mySetting: String by ksafe(defaultValue = "default")
 *
 * // Explicit key "custom_key" is used
 * var counter: Int by ksafe(defaultValue = 0, key = "custom_key", encrypted = false)
 * ```
 *
 * @param T The type of the property.
 * @param defaultValue The default value to return if the key is not found.
 * @param key Optional explicit key. If null, the property name is used.
 * @param encrypted Whether the value should be encrypted (defaults to true).
 * @return A [ReadWriteProperty] delegate.
 */
inline operator fun <reified T> KSafe.invoke(
    defaultValue: T,
    key: String? = null,
    encrypted: Boolean = true
): ReadWriteProperty<Any?, T> {
    val ksafeInstance = this

    return object : ReadWriteProperty<Any?, T> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): T {
            // Because this object expression is inside an inline function with reified T,
            // T is reified here. We explicitly pass it to getDirect.
            return ksafeInstance.getDirect<T>(key = key ?: property.name, defaultValue, encrypted)
        }

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
            // Similarly, T is reified here. We explicitly pass it to putDirect.
            // Updates memory cache instantly and writes to disk in background (Async)
            ksafeInstance.putDirect<T>(key = key ?:property.name, value, encrypted)
        }
    }
}
