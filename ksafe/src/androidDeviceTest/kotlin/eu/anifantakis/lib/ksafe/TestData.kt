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