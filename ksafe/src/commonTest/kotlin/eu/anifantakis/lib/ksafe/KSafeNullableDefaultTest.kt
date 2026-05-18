package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Dedicated, **intentionally small** regression suite for issue #31:
 * retrieving a `@Serializable` class with a *nullable* default
 * (`null as T?`) must deserialize the value, not return the raw stored
 * JSON string (`ClassCastException: String cannot be cast to <Type>`).
 *
 * This is deliberately NOT a method on [KSafeTest]. The legacy Kotlin/JS
 * `kotlin-test` runner silently truncates the trailing `@Test`s of that
 * oversized class (it stops registering past ~62), so a regression appended
 * there is compiled but never executed on Kotlin/JS — with zero failure
 * signal. Small focused classes register fully on every target (verified),
 * so cross-platform regressions belong here, one concern per class.
 *
 * Subclasses supply a platform [KSafe] via [newKSafe], mirroring
 * [KSafeTest]'s contract.
 */
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

    /**
     * `get`/`getFlow` with a nullable `@Serializable` default whose first
     * property is a primitive must round-trip on every platform.
     */
    @Test
    fun issue31_nullableDefault_complexType_roundTrips() = runTest {
        val ksafe = createKSafe()
        val value = Issue31Data(name = "alice", count = 7)

        // Plain path — exercises convertStoredValue / primitiveKindOrNull,
        // the exact regression site.
        ksafe.put("issue31_plain", value, KSafeWriteMode.Plain)
        assertEquals(value, ksafe.get("issue31_plain", null as Issue31Data?))
        assertEquals(value, ksafe.getFlow("issue31_plain", null as Issue31Data?).first())

        // Encrypted (default) path with a nullable default.
        ksafe.put("issue31_enc", value)
        assertEquals(value, ksafe.get("issue31_enc", null as Issue31Data?))

        // Non-null default still works (the path that already worked).
        assertEquals(value, ksafe.get("issue31_plain", Issue31Data("", 0)))

        // Missing key with a nullable default returns null, not a String.
        assertNull(ksafe.get("issue31_absent", null as Issue31Data?))
    }
}
