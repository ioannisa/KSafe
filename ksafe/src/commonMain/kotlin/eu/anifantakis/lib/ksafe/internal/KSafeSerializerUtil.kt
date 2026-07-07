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
 * [PrimitiveKind] of the serializer (nullable wrappers report the wrapped kind), or
 * `null` for non-primitives. Dispatching on the descriptor is required where runtime
 * type checks collapse — on Kotlin/JS `0f is Int` is true.
 */
@PublishedApi
internal fun primitiveKindOrNull(serializer: KSerializer<*>): PrimitiveKind? {
    // `.nullable` delegates `kind` to the wrapped type. Do NOT descend via
    // getElementDescriptor(0): on a nullable @Serializable class that walks into the
    // class's first field and can misreport it as a primitive.
    return serializer.descriptor.kind as? PrimitiveKind
}

/**
 * Like [primitiveKindOrNull], but only for the built-in primitive serializers.
 * Custom serializers (Duration, Uuid, kotlinx-datetime) declare primitive descriptors
 * yet are JSON-encoded by the write path; gating on the built-in serialName keeps the
 * read fast-path symmetric with what the write path stores raw. Nullable serialNames
 * carry a trailing `?`; inline (value-class) descriptors are excluded; BYTE/SHORT/CHAR
 * return null because they always round-trip through JSON.
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
