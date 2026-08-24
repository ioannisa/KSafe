package eu.anifantakis.lib.ksafe

import androidx.compose.runtime.Stable
import kotlinx.serialization.KSerializer
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * The handle returned by `ksafe(default, key)` and the mode-typed views' `invoke`. Dual-use:
 *
 * - **As a delegate** — `var counter by ksafe(0)`: the property name becomes the storage
 *   key when [key] is null, exactly as always.
 * - **Directly, without `by`** — `val counter = ksafe(0, key = "counter"); counter.value++`:
 *   [value] reads through the hot cache ([KSafe.getDirect]) and writes fire-and-forget
 *   ([KSafe.putDirect]) with the [KSafeWriteMode] captured at creation.
 *
 * Direct access requires an explicit [key]: a plain `=` assignment carries no property name
 * Kotlin could hand to KSafe, so a key-less handle can only be used with `by` — touching
 * [value] on one throws [IllegalStateException].
 */
@Stable
class KSafeReference<T> @PublishedApi internal constructor(
    private val ksafe: KSafe,
    private val serializer: KSerializer<T>,
    private val defaultValue: T,
    /** The storage key, or null when the handle is delegate-only (the property name becomes the key). */
    val key: String?,
    private val mode: KSafeWriteMode,
) : ReadWriteProperty<Any?, T> {

    /**
     * The persisted value, or the creation-time default while none exists. Setting persists
     * immediately (fire-and-forget, like [KSafe.putDirect]). Requires an explicit [key].
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
