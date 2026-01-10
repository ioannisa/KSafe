package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests for [KSafeMemoryPolicy] enum.
 */
class KSafeMemoryPolicyTest {

    // ============ ENUM VALUES ============

    /** Verifies enum has exactly 2 values: PLAIN_TEXT and ENCRYPTED */
    @Test
    fun memoryPolicy_hasCorrectNumberOfValues() {
        val values = KSafeMemoryPolicy.entries
        assertEquals(2, values.size, "KSafeMemoryPolicy should have exactly 2 values")
    }

    /** Verifies PLAIN_TEXT value exists in enum */
    @Test
    fun memoryPolicy_containsPlainText() {
        val values = KSafeMemoryPolicy.entries
        assertTrue(values.contains(KSafeMemoryPolicy.PLAIN_TEXT))
    }

    /** Verifies ENCRYPTED value exists in enum */
    @Test
    fun memoryPolicy_containsEncrypted() {
        val values = KSafeMemoryPolicy.entries
        assertTrue(values.contains(KSafeMemoryPolicy.ENCRYPTED))
    }

    // ============ ORDINAL ORDER ============

    /** Verifies ordinal values: PLAIN_TEXT=0, ENCRYPTED=1 */
    @Test
    fun memoryPolicy_ordinalOrder() {
        // Verify the order as defined in the enum
        assertEquals(0, KSafeMemoryPolicy.PLAIN_TEXT.ordinal)
        assertEquals(1, KSafeMemoryPolicy.ENCRYPTED.ordinal)
    }

    // ============ NAME VALUES ============

    /** Verifies PLAIN_TEXT.name returns "PLAIN_TEXT" */
    @Test
    fun memoryPolicy_plainText_name() {
        assertEquals("PLAIN_TEXT", KSafeMemoryPolicy.PLAIN_TEXT.name)
    }

    /** Verifies ENCRYPTED.name returns "ENCRYPTED" */
    @Test
    fun memoryPolicy_encrypted_name() {
        assertEquals("ENCRYPTED", KSafeMemoryPolicy.ENCRYPTED.name)
    }

    // ============ VALUE OF ============

    /** Verifies valueOf("PLAIN_TEXT") returns correct enum value */
    @Test
    fun memoryPolicy_valueOf_plainText() {
        val policy = KSafeMemoryPolicy.valueOf("PLAIN_TEXT")
        assertEquals(KSafeMemoryPolicy.PLAIN_TEXT, policy)
    }

    /** Verifies valueOf("ENCRYPTED") returns correct enum value */
    @Test
    fun memoryPolicy_valueOf_encrypted() {
        val policy = KSafeMemoryPolicy.valueOf("ENCRYPTED")
        assertEquals(KSafeMemoryPolicy.ENCRYPTED, policy)
    }

    // ============ USE CASES ============

    /** Verifies when expression covers all enum values exhaustively */
    @Test
    fun memoryPolicy_whenExpression_exhaustive() {
        KSafeMemoryPolicy.entries.forEach { policy ->
            val description = when (policy) {
                KSafeMemoryPolicy.PLAIN_TEXT -> "Plain text in memory for performance"
                KSafeMemoryPolicy.ENCRYPTED -> "Encrypted in memory for security"
            }
            assertTrue(description.isNotEmpty())
        }
    }

    /** Verifies enum comparison behavior */
    @Test
    fun memoryPolicy_comparison() {
        // Verify comparison works as expected for enums
        assertEquals(KSafeMemoryPolicy.PLAIN_TEXT, KSafeMemoryPolicy.PLAIN_TEXT)
        assertEquals(KSafeMemoryPolicy.ENCRYPTED, KSafeMemoryPolicy.ENCRYPTED)
        assertTrue(KSafeMemoryPolicy.PLAIN_TEXT != KSafeMemoryPolicy.ENCRYPTED)
    }
}
