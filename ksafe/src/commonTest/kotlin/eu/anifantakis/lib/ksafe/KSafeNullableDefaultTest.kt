package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Locks in: retrieving a `@Serializable` class with a nullable default (`null as T?`) deserializes the value instead of returning the raw stored JSON string.
 */
// Kept as its own small class: the Kotlin/JS kotlin-test runner stops registering @Tests past
// ~62 in an oversized class, so cross-platform regressions live in focused classes, one concern each.
abstract class KSafeNullableDefaultTest {

    private val tracked = mutableListOf<KSafe>()

    protected abstract fun newKSafe(fileName: String? = null): KSafe

    private fun createKSafe(fileName: String? = null): KSafe =
        newKSafe(fileName).also { tracked += it }

    @AfterTest
    fun tearDown() {
        tracked.forEach { runCatching { it.close() } }
        tracked.clear()
    }

    @Test
    fun issue31_nullableDefault_complexType_roundTrips() = runTest {
        val ksafe = createKSafe()
        val value = Issue31Data(name = "alice", count = 7)

        // Plain path exercises the nullable-default type detection.
        ksafe.put("issue31_plain", value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get("issue31_plain", null as Issue31Data?))
        assertEquals(value, ksafe.getFlow("issue31_plain", null as Issue31Data?).first())

        ksafe.put("issue31_enc", value)
        assertEquals(value, ksafe.get("issue31_enc", null as Issue31Data?))

        assertEquals(value, ksafe.get("issue31_plain", Issue31Data("", 0)))

        // Missing key with a nullable default returns null, not a String.
        assertNull(ksafe.get("issue31_absent", null as Issue31Data?))
    }
}
