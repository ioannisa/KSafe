package eu.anifantakis.lib.ksafe.internal

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.json.Json

/**
 * Returns true if the serializer represents a String or nullable-String type.
 * Used by [convertStoredValueRaw] to avoid JSON-parsing plain string values.
 */
@PublishedApi
internal fun isStringSerializer(serializer: KSerializer<*>): Boolean {
    return primitiveKindOrNull(serializer) == PrimitiveKind.STRING
}

/**
 * Returns the [PrimitiveKind] of the serializer, unwrapping nullable wrappers,
 * or `null` if the serializer's descriptor is not a primitive.
 *
 * This is the robust way to dispatch a stored `String` back into its declared
 * type on targets where runtime type checks collapse (notably Kotlin/JS, where
 * `0f is Int` returns `true` because JS represents `0f` as the integer `0`).
 */
@PublishedApi
internal fun primitiveKindOrNull(serializer: KSerializer<*>): PrimitiveKind? {
    // kotlinx-serialization's `.nullable` descriptor delegates `kind` (and
    // `elementsCount`) to the wrapped type, so `T?` reports the same kind as
    // `T`: `Int?` -> INT, `@Serializable class Foo?` -> CLASS. We must NOT
    // descend via getElementDescriptor(0) on a nullable wrapper — for a
    // nullable @Serializable class that would walk into the class's first
    // *field* and misreport e.g. a class with a leading String field as
    // PrimitiveKind.STRING, causing the stored JSON to be returned verbatim
    // (ClassCastException: String cannot be cast to <Type>). See issue #31.
    return serializer.descriptor.kind as? PrimitiveKind
}

/**
 * Like [primitiveKindOrNull], but returns a kind ONLY for the **built-in**
 * primitive serializers (`kotlin.Int`, `kotlin.String`, …).
 *
 * Custom serializers frequently declare a primitive descriptor kind
 * (`PrimitiveSerialDescriptor`) while their runtime values are NOT that Kotlin
 * primitive — `kotlin.time.Duration` and `kotlin.uuid.Uuid` are STRING-kind,
 * kotlinx-datetime types and the common hand-written custom-serializer pattern
 * likewise. The plain WRITE path dispatches on the runtime type and
 * JSON-encodes those values, so a read taking the primitive fast-path returned
 * the stored JSON verbatim (quote characters included) and the caller's
 * reified cast threw ClassCastException (review R5). Gating on the built-in
 * serialName keeps the fast-path exactly for the values the write path stores
 * raw, and routes everything else through the JSON branch that decodes them
 * correctly — making the read dispatch symmetric with the write dispatch.
 *
 * Nullable wrappers report the wrapped serialName plus a trailing `?`, hence
 * the suffix strip. Inline (value-class) descriptors are excluded outright.
 * BYTE/SHORT/CHAR return null: no write path stores those raw, so they have
 * always round-tripped through JSON.
 */
@PublishedApi
internal fun builtInPrimitiveKindOrNull(serializer: KSerializer<*>): PrimitiveKind? {
    val descriptor = serializer.descriptor
    val kind = descriptor.kind as? PrimitiveKind ?: return null
    if (descriptor.isInline) return null
    val expected = when (kind) {
        PrimitiveKind.BOOLEAN -> "kotlin.Boolean"
        PrimitiveKind.INT -> "kotlin.Int"
        PrimitiveKind.LONG -> "kotlin.Long"
        PrimitiveKind.FLOAT -> "kotlin.Float"
        PrimitiveKind.DOUBLE -> "kotlin.Double"
        PrimitiveKind.STRING -> "kotlin.String"
        else -> return null
    }
    return if (descriptor.serialName.removeSuffix("?") == expected) kind else null
}

/**
 * JSON-decode helper that works with erased serializer types.
 */
@PublishedApi
internal fun jsonDecode(json: Json, serializer: KSerializer<*>, jsonString: String): Any? {
    @Suppress("UNCHECKED_CAST")
    return json.decodeFromString(serializer as KSerializer<Any?>, jsonString)
}

/**
 * JSON-encode helper that works with erased serializer types.
 */
@PublishedApi
internal fun jsonEncode(json: Json, serializer: KSerializer<*>, value: Any?): String {
    @Suppress("UNCHECKED_CAST")
    return json.encodeToString(serializer as SerializationStrategy<Any?>, value)
}
