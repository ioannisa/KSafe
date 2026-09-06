package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.NULL_SENTINEL
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.decodePlainString
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.isNullSentinel
import eu.anifantakis.lib.ksafe.internal.builtInPrimitiveKindOrNull
import eu.anifantakis.lib.ksafe.internal.jsonDecode
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.KSerializer

// A stored null resolves to null only for a nullable T: a bare null passes the erased `as T` cast
// and defers an NPE to an unrelated later use site.
internal fun nullOrDefault(defaultValue: Any?, serializer: KSerializer<*>): Any? =
    if (serializer.descriptor.isNullable) null else defaultValue

internal fun KSafeCore.convertStoredValue(storedValue: Any?, defaultValue: Any?, serializer: KSerializer<*>): Any? {
    if (storedValue == null) return defaultValue
    if (isNullSentinel(storedValue)) return nullOrDefault(defaultValue, serializer)

    // Dispatch on the serializer's kind, not defaultValue's class: survives a null default and is
    // JS-safe (`0f is Int` on Kotlin/JS). Built-ins only: a custom serializer with a primitive
    // descriptor is written as JSON and must decode in the else branch, or the reified cast throws.
    return when (builtInPrimitiveKindOrNull(serializer)) {
        kotlinx.serialization.descriptors.PrimitiveKind.BOOLEAN -> when (storedValue) {
            is Boolean -> storedValue
            is String -> storedValue.toBooleanStrictOrNull() ?: defaultValue
            else -> defaultValue
        }
        // Numeric kinds coerce across Int/Long/Float/Double so a key's declared type can change
        // between app versions; out-of-range or fractional reads yield the default, never truncate.
        kotlinx.serialization.descriptors.PrimitiveKind.INT -> when (storedValue) {
            is Int -> storedValue
            is Long -> if (storedValue in Int.MIN_VALUE..Int.MAX_VALUE) storedValue.toInt() else defaultValue
            is Float -> storedValue.toDouble().toLongExactOrNull()
                ?.let { if (it in Int.MIN_VALUE..Int.MAX_VALUE) it.toInt() else null } ?: defaultValue
            is Double -> storedValue.toLongExactOrNull()
                ?.let { if (it in Int.MIN_VALUE..Int.MAX_VALUE) it.toInt() else null } ?: defaultValue
            is String -> storedValue.toIntOrNull() ?: defaultValue
            else -> defaultValue
        }
        kotlinx.serialization.descriptors.PrimitiveKind.LONG -> when (storedValue) {
            is Long -> storedValue
            is Int -> storedValue.toLong()
            is Float -> storedValue.toDouble().toLongExactOrNull() ?: defaultValue
            is Double -> storedValue.toLongExactOrNull() ?: defaultValue
            is String -> storedValue.toLongOrNull() ?: defaultValue
            else -> defaultValue
        }
        kotlinx.serialization.descriptors.PrimitiveKind.FLOAT -> when (storedValue) {
            is Float -> storedValue
            // A finite Double that overflows Float falls back instead of becoming Infinity.
            is Double -> {
                val f = storedValue.toFloat()
                if (f.isInfinite() && storedValue.isFinite()) defaultValue else f
            }
            is Int -> storedValue.toFloat()
            is Long -> storedValue.toFloat()
            is String -> storedValue.toFloatOrNull() ?: defaultValue
            else -> defaultValue
        }
        kotlinx.serialization.descriptors.PrimitiveKind.DOUBLE -> when (storedValue) {
            is Double -> storedValue
            is Float -> storedValue.toDouble()
            is Int -> storedValue.toDouble()
            is Long -> storedValue.toDouble()
            is String -> storedValue.toDoubleOrNull() ?: defaultValue
            else -> defaultValue
        }
        kotlinx.serialization.descriptors.PrimitiveKind.STRING -> when (storedValue) {
            is String -> if (storedValue == NULL_SENTINEL) null else decodePlainString(storedValue)
            else -> defaultValue
        }
        else -> {
            // Complex `@Serializable` type — expect a JSON string. A raw primitive here would
            // flow into the caller's reified `as T` cast and throw CCE, so fall back instead.
            if (storedValue !is String) return defaultValue
            if (storedValue == NULL_SENTINEL) return null
            try {
                jsonDecode(json, serializer, storedValue)
            } catch (e: Throwable) {
                if (e is CancellationException) throw e
                defaultValue
            }
        }
    }
}

/** This Double as a Long when it is finite, integral and in range; null otherwise. */
private fun Double.toLongExactOrNull(): Long? {
    if (!isFinite() || this != kotlin.math.floor(this)) return null
    // Long.MAX_VALUE.toDouble() rounds up to 2^63, so the upper bound is strict.
    if (this < Long.MIN_VALUE.toDouble() || this >= Long.MAX_VALUE.toDouble()) return null
    return toLong()
}
