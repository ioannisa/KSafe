package eu.anifantakis.lib.ksafe.internal.coreparts

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.NULL_SENTINEL
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.decodePlainString
import eu.anifantakis.lib.ksafe.internal.KSafeCore.Companion.isNullSentinel
import eu.anifantakis.lib.ksafe.internal.builtInPrimitiveKindOrNull
import eu.anifantakis.lib.ksafe.internal.jsonDecode
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.KSerializer

// A stored explicit null (NULL_SENTINEL) resolves to null only when the caller's T is nullable;
// for a non-nullable T it yields the caller's default. Returning a bare null for a non-nullable
// T passes the erased `as T` cast and defers an NPE to an unrelated later use site.
internal fun nullOrDefault(defaultValue: Any?, serializer: KSerializer<*>): Any? =
    if (serializer.descriptor.isNullable) null else defaultValue

internal fun KSafeCore.convertStoredValue(storedValue: Any?, defaultValue: Any?, serializer: KSerializer<*>): Any? {
    if (storedValue == null) return defaultValue
    if (isNullSentinel(storedValue)) return nullOrDefault(defaultValue, serializer)

    // Dispatch on the serializer's primitive kind, not defaultValue's runtime class: that
    // survives a null default and is JS-safe (on Kotlin/JS `0f is Int` is true). Built-in
    // primitives ONLY — a custom serializer with a primitive descriptor (Duration, Uuid,
    // datetime) is JSON-encoded by the write path, so it must round-trip through the JSON
    // else-branch; the primitive fast-path would return stored JSON verbatim and the
    // caller's reified cast would throw CCE.
    return when (builtInPrimitiveKindOrNull(serializer)) {
        kotlinx.serialization.descriptors.PrimitiveKind.BOOLEAN -> when (storedValue) {
            is Boolean -> storedValue
            is String -> storedValue.toBooleanStrictOrNull() ?: defaultValue
            else -> defaultValue
        }
        // Numeric kinds coerce across the whole Int/Long/Float/Double matrix so a key's
        // declared type can change between app versions without losing data: coerce when the
        // value is faithfully representable, else fall back to the default (out-of-range or
        // fractional reads) rather than silently truncating or wrapping. Widening conversions
        // are exact or lose only precision at large magnitudes.
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
            // Narrowing Double -> Float, mirroring the Long -> Int guard: a finite
            // Double that overflows Float's range falls back to the default rather
            // than silently becoming Infinity.
            is Double -> {
                val f = storedValue.toFloat()
                if (f.isInfinite() && storedValue.isFinite()) defaultValue else f
            }
            // Int / Long -> Float never overflows Float's range; large magnitudes
            // lose precision, which is the expected narrowing cost.
            is Int -> storedValue.toFloat()
            is Long -> storedValue.toFloat()
            is String -> storedValue.toFloatOrNull() ?: defaultValue
            else -> defaultValue
        }
        kotlinx.serialization.descriptors.PrimitiveKind.DOUBLE -> when (storedValue) {
            is Double -> storedValue
            is Float -> storedValue.toDouble()   // widening — lossless
            is Int -> storedValue.toDouble()     // exact — Int fits Double's 53-bit mantissa
            is Long -> storedValue.toDouble()    // representable; magnitudes > 2^53 lose precision (expected)
            is String -> storedValue.toDoubleOrNull() ?: defaultValue
            else -> defaultValue
        }
        kotlinx.serialization.descriptors.PrimitiveKind.STRING -> when (storedValue) {
            is String -> if (storedValue == NULL_SENTINEL) null else decodePlainString(storedValue)
            else -> defaultValue
        }
        else -> {
            // Complex `@Serializable` type — expect a JSON string. A non-String here is a
            // genuine type mismatch (a primitive persisted via KSafeWriteMode.Plain, read back
            // after the key's declared type changed to a complex type across app versions), so
            // fall back to the default like every other mismatch arm above. Returning the raw
            // primitive instead would flow into the caller's reified `... as T` cast and throw
            // ClassCastException, crashing the property access / collecting scope.
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

/**
 * Returns this Double as a Long if it is finite, has no fractional part, and
 * fits within Long's range; otherwise null. Used for decimal -> integer reads
 * (see [convertStoredValue]) so a fractional or out-of-range decimal falls back
 * to the caller's default instead of being silently truncated or wrapped.
 */
private fun Double.toLongExactOrNull(): Long? {
    if (!isFinite() || this != kotlin.math.floor(this)) return null
    // Long.MAX_VALUE.toDouble() rounds up to 2^63 (out of Long range), so the
    // upper bound is strict; Long.MIN_VALUE (-2^63) is exactly representable.
    if (this < Long.MIN_VALUE.toDouble() || this >= Long.MAX_VALUE.toDouble()) return null
    return toLong()
}
