package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * A stored explicit null must resolve to null only for a nullable read type; a non-nullable read
 * gets the caller's default rather than a bare null that would defer an NPE to a later use site.
 */
class JvmLowFixesTest {

    private val tracked = mutableListOf<KSafe>()
    private var counter = 0
    private fun uniqueName(): String = "lowfix${System.nanoTime()}_${counter++}"
    private fun newKSafe(): KSafe =
        KSafe(fileName = uniqueName(), testEngine = FakeEncryption()).also { tracked += it }

    @AfterTest
    fun tearDown() {
        tracked.forEach { runCatching { it.close() } }
        tracked.clear()
    }

    @Test
    fun storedNull_plain_readAsNonNullable_returnsDefault_nullablePreservesNull() = runTest {
        val ksafe = newKSafe()
        ksafe.put<String?>("token", null, KSafeWriteMode.Plain)

        assertEquals("fallback", ksafe.get<String>("token", "fallback"), "non-nullable read must get the default")
        assertNull(ksafe.get<String?>("token", "fallback"), "nullable read must preserve the explicit null")
    }

    @Test
    fun storedNull_encrypted_readAsNonNullable_returnsDefault_nullablePreservesNull() = runTest {
        val ksafe = newKSafe()
        ksafe.put<String?>("secret", null) // default encrypted

        assertEquals("fallback", ksafe.get<String>("secret", "fallback"), "non-nullable read must get the default")
        assertNull(ksafe.get<String?>("secret", "fallback"), "nullable read must preserve the explicit null")
    }
}
