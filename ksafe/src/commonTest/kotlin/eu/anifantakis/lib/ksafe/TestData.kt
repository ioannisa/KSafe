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
 * Fixture: a `@Serializable` class whose **first field is a String**.
 * Retrieving it with a nullable default (`null as Issue31Data?`) must not
 * misdetect the type as `PrimitiveKind.STRING` and return the raw JSON
 * string — that fails the caller's reified cast.
 */
@Serializable
data class Issue31Data(
    val name: String,
    val count: Int,
)