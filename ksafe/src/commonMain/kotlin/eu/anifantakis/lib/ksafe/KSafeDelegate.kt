package eu.anifantakis.lib.ksafe

import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * Allows eu.anifantakis.ksafe.KSafe to be used with property delegation.
 *
 * Usage:
 * ```
 * val eu.anifantakis.ksafe.KSafe: eu.anifantakis.ksafe.KSafe = // ... obtain your eu.anifantakis.ksafe.KSafe instance
 * var mySetting: String by eu.anifantakis.ksafe.KSafe(defaultValue = "default", encrypted = true)
 * ```
 *
 * @param T The type of the property.
 * @param defaultValue The default value to return if the key is not found.
 * @param encrypted Whether the value should be encrypted (defaults to true).
 * @return A ReadWriteProperty delegate.
 */
inline operator fun <reified T> KSafe.invoke(
    defaultValue: T,
    key: String? = null,
    encrypted: Boolean = true
): ReadWriteProperty<Any?, T> {
    // 'this' inside this inline function refers to the eu.anifantakis.ksafe.KSafe instance
    // on which 'eu.anifantakis.ksafe.invoke' is called.
    val ksafeInstance = this

    return object : ReadWriteProperty<Any?, T> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): T {
            // Because this object expression is inside an inline function with reified T,
            // T is reified here. We explicitly pass it to getDirect.
            return ksafeInstance.getDirect<T>(key = key ?: property.name, defaultValue, encrypted)
        }

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
            // Similarly, T is reified here. We explicitly pass it to putDirect.
            ksafeInstance.putDirect<T>(key = key ?:property.name, value, encrypted)
        }
    }
}