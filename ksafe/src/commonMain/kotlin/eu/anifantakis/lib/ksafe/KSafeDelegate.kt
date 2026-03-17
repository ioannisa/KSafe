package eu.anifantakis.lib.ksafe

import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * Non-inline delegate class that holds a [KSerializer] captured once at creation time.
 * This prevents the entire getDirect/putDirect inline chain from being duplicated
 * at every property declaration site (~250 lines per delegate → ~5 lines).
 */
@PublishedApi
internal class KSafeDelegate<T>(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    private val key: String?,
    private val mode: KSafeWriteMode
) : ReadWriteProperty<Any?, T> {
    override fun getValue(thisRef: Any?, property: KProperty<*>): T {
        @Suppress("UNCHECKED_CAST")
        return ksafe.getDirectRaw(key ?: property.name, defaultValue, serializer) as T
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        ksafe.putDirectRaw(key ?: property.name, value, mode, serializer)
    }
}

/**
 * Allows KSafe to be used with property delegation.
 *
 * Uses non-blocking [KSafe.getDirect]/[KSafe.putDirect] under the hood.
 * Default mode is encrypted.
 */
inline operator fun <reified T> KSafe.invoke(
    defaultValue: T,
    key: String? = null,
    mode: KSafeWriteMode = KSafeWriteMode.Encrypted()
): ReadWriteProperty<Any?, T> = KSafeDelegate(this, serializer<T>(), defaultValue, key, mode)

/** @deprecated Use [invoke] with [KSafeWriteMode] parameter instead. */
@Deprecated(
    "Replace \"encrypted\" parameter with \"mode\" parameter.\n\nGuideline: [Deprecated] -> [New]:\nencrypted=true -> KSafeWriteMode.Encrypted()\nencrypted=false -> KSafeWriteMode.Plain",
    ReplaceWith("invoke(defaultValue, key, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)")
)
inline operator fun <reified T> KSafe.invoke(
    defaultValue: T,
    key: String? = null,
    encrypted: Boolean
): ReadWriteProperty<Any?, T> =
    invoke(defaultValue, key, if (encrypted) KSafeWriteMode.Encrypted() else KSafeWriteMode.Plain)
