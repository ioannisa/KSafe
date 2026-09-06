package eu.anifantakis.lib.ksafe.internal

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.json.Json

/** True if the serializer represents a (nullable) String type. */
@PublishedApi
internal fun isStringSerializer(serializer: KSerializer<*>): Boolean {
    return primitiveKindOrNull(serializer) == PrimitiveKind.STRING
}

/**
 * [PrimitiveKind] of the serializer, or null for non-primitives; a nullable wrapper reports
 * the wrapped kind.
 */
@PublishedApi
internal fun primitiveKindOrNull(serializer: KSerializer<*>): PrimitiveKind? {
    // Descriptor, not a runtime check — on Kotlin/JS `0f is Int` is true. Do NOT descend via
    // getElementDescriptor(0): on a nullable @Serializable class it misreports the first field.
    return serializer.descriptor.kind as? PrimitiveKind
}

/**
 * Like [primitiveKindOrNull] but only for the built-in primitive serializers: custom ones
 * (Duration, Uuid, datetime) and BYTE/SHORT/CHAR are JSON-encoded by the write path, so gating
 * on the built-in serialName keeps the read fast-path symmetric with it.
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

/** JSON-decode helper for erased serializer types. */
@PublishedApi
internal fun jsonDecode(json: Json, serializer: KSerializer<*>, jsonString: String): Any? {
    @Suppress("UNCHECKED_CAST")
    return json.decodeFromString(serializer as KSerializer<Any?>, jsonString)
}

/** JSON-encode helper for erased serializer types. */
@PublishedApi
internal fun jsonEncode(json: Json, serializer: KSerializer<*>, value: Any?): String {
    @Suppress("UNCHECKED_CAST")
    return json.encodeToString(serializer as SerializationStrategy<Any?>, value)
}
