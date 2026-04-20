package eu.anifantakis.lib.ksafe

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
    var desc = serializer.descriptor
    if (desc.isNullable && desc.elementsCount > 0) {
        desc = desc.getElementDescriptor(0)
    }
    return desc.kind as? PrimitiveKind
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
