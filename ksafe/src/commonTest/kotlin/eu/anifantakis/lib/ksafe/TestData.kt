package eu.anifantakis.lib.ksafe

import kotlinx.serialization.Serializable

@Serializable
data class TestData(
    val id: Int,
    val name: String,
    val active: Boolean,
    val scores: List<Double>,
    val metadata: Map<String, String>
)

/**
 * Regression fixture for issue #31: a `@Serializable` class whose **first
 * field is a String**. Before the `primitiveKindOrNull` fix, retrieving this
 * with a nullable default (`null as Issue31Data?`) misdetected the type as
 * `PrimitiveKind.STRING` and returned the raw JSON string, throwing
 * `ClassCastException: String cannot be cast to Issue31Data`.
 */
@Serializable
data class Issue31Data(
    val name: String,
    val count: Int,
)