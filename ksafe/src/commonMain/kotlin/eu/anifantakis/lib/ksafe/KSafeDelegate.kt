package eu.anifantakis.lib.ksafe

import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * Allows KSafe to be used with property delegation.
 *
 * Note: This uses runBlocking internally for synchronous behavior.
 * For better performance in coroutines, use the suspend functions directly.
 * You can use flows to achieve much the same behavior.
 *
 * Usage:
 * ```
 * val ksafe: KSafe = // ... obtain your KSafe instance
 * var mySetting: String by ksafe(defaultValue = "default", encrypted = true)
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
    val ksafeInstance = this

    return object : ReadWriteProperty<Any?, T> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): T {
            // Because this object expression is inside an inline function with reified T,
            // T is reified here. We explicitly pass it to getDirect.
            return ksafeInstance.getDirect<T>(key = key ?: property.name, defaultValue, encrypted)
        }

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
            // Similarly, T is reified here. We explicitly pass it to putDirect.
            // putDirect uses runBlocking to behave synchronously on JVM so a read right after a write is consistent.
            // an immedicate read after a write can therefore give you stale data.
            ksafeInstance.putDirect<T>(key = key ?:property.name, value, encrypted)
        }
    }
}
