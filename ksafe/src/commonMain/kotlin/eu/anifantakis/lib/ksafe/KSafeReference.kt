package eu.anifantakis.lib.ksafe

import kotlinx.serialization.KSerializer
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * The handle returned by `ksafe(default, key)` and the mode views' `invoke`. Use it as a delegate
 * (`var counter by ksafe(0)`), where the property name becomes the key, or keep it in a `val` and
 * go through [value], which needs an explicit [key]. Reads come from the cache via
 * [KSafe.getDirect], blocking once while it loads and returning the default when nothing is
 * stored; writes go through [KSafe.putDirect] in the mode the handle was created with.
 */
class KSafeReference<T> @PublishedApi internal constructor(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    /** The storage key, or `null` when the handle is delegate-only and the property name is used
     *  instead. */
    val key: String?,
    private val mode: KSafeWriteMode,
) : ReadWriteProperty<Any?, T> {

    /**
     * The stored value, or the creation-time default. Setting persists fire-and-forget. Both
     * throw [IllegalStateException] when the handle was created without a [key]. A change here
     * recomposes nothing; in composition use `rememberKSafeState` from `:ksafe-compose` or
     * collect [KSafe.getStateFlow].
     */
    var value: T
        get() = read(requireKey())
        set(newValue) = write(requireKey(), newValue)

    override fun getValue(thisRef: Any?, property: KProperty<*>): T =
        read(key ?: property.name)

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) =
        write(key ?: property.name, value)

    private fun requireKey(): String = key ?: error(
        "This KSafe handle was created without a key, so .value cannot know where to read or " +
            "write. Pass key = … at creation for direct access, or use the handle as a `by` " +
            "delegate, where the property name becomes the key."
    )

    private fun read(actualKey: String): T {
        @Suppress("UNCHECKED_CAST")
        return ksafe.core.getDirectRaw(actualKey, defaultValue, serializer) as T
    }

    private fun write(actualKey: String, newValue: T) {
        ksafe.core.putDirectRaw(actualKey, newValue, mode, serializer)
    }
}
