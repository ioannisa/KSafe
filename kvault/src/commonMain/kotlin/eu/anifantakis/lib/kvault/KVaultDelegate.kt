package eu.anifantakis.lib.kvault

import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * Allows eu.anifantakis.kvault.KVault to be used with property delegation.
 *
 * Usage:
 * ```
 * val eu.anifantakis.kvault.KVault: eu.anifantakis.kvault.KVault = // ... obtain your eu.anifantakis.kvault.KVault instance
 * var mySetting: String by eu.anifantakis.kvault.KVault(defaultValue = "default", encrypted = true)
 * ```
 *
 * @param T The type of the property.
 * @param defaultValue The default value to return if the key is not found.
 * @param encrypted Whether the value should be encrypted (defaults to true).
 * @return A ReadWriteProperty delegate.
 */
inline operator fun <reified T> KVault.invoke(
    defaultValue: T,
    encrypted: Boolean = true
): ReadWriteProperty<Any?, T> {
    // 'this' inside this inline function refers to the eu.anifantakis.kvault.KVault instance
    // on which 'eu.anifantakis.kvault.invoke' is called.
    val kvaultInstance = this

    return object : ReadWriteProperty<Any?, T> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): T {
            // Because this object expression is inside an inline function with reified T,
            // T is reified here. We explicitly pass it to getDirect.
            return kvaultInstance.getDirect<T>(property.name, defaultValue, encrypted)
        }

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
            // Similarly, T is reified here. We explicitly pass it to putDirect.
            kvaultInstance.putDirect<T>(property.name, value, encrypted)
        }
    }
}