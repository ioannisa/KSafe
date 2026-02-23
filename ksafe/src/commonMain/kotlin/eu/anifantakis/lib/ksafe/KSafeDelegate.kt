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
 * // Explicit key "custom_key" is used, no encryption
 * var counter: Int by ksafe(defaultValue = 0, key = "custom_key", protection = KSafeProtection.NONE)
 *
 * // Hardware-isolated encryption (StrongBox / Secure Enclave)
 * var secret: String by ksafe(defaultValue = "", protection = KSafeProtection.HARDWARE_ISOLATED)
 * ```
 *
 * **For biometric protection**, use [KSafe.verifyBiometric] or [KSafe.verifyBiometricDirect]
 * before modifying the value:
 * ```kotlin
 * ksafe.verifyBiometricDirect("Authenticate") { success ->
 *     if (success) {
 *         counter++
 *     }
 * }
 * ```
 *
 * @param T The type of the property.
 * @param defaultValue The default value to return if the key is not found.
 * @param key Optional explicit key. If null, the property name is used.
 * @param protection The encryption/storage protection level. Defaults to [KSafeProtection.DEFAULT].
 * @return A [ReadWriteProperty] delegate.
 */
inline operator fun <reified T> KSafe.invoke(
    defaultValue: T,
    key: String? = null,
    protection: KSafeProtection = KSafeProtection.DEFAULT
): ReadWriteProperty<Any?, T> {
    val ksafeInstance = this

    return object : ReadWriteProperty<Any?, T> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): T {
            // Because this object expression is inside an inline function with reified T,
            // T is reified here. We explicitly pass it to getDirect.
            return ksafeInstance.getDirect<T>(key = key ?: property.name, defaultValue)
        }

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
            // Similarly, T is reified here. We explicitly pass it to putDirect.
            // Updates memory cache instantly and writes to disk in background (Async)
            ksafeInstance.putDirect<T>(key = key ?: property.name, value, protection)
        }
    }
}

/** @deprecated Use [invoke] with [KSafeProtection] parameter instead. */
@Deprecated(
    "Replace \"encrypted\" parameter with \"protection\" parameter. \n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeProtection.DEFAULT\nencrypted=false -> KSafeProtection.NONE\n\nNote: You don't need to include a protection reference if you aim for \"DEFAULT\" protection (it is assumed and you can omit it).",
    ReplaceWith("invoke(defaultValue, key, if (encrypted) KSafeProtection.DEFAULT else KSafeProtection.NONE)")
)
inline operator fun <reified T> KSafe.invoke(
    defaultValue: T,
    key: String? = null,
    encrypted: Boolean
): ReadWriteProperty<Any?, T> =
    invoke(defaultValue, key, if (encrypted) KSafeProtection.DEFAULT else KSafeProtection.NONE)
