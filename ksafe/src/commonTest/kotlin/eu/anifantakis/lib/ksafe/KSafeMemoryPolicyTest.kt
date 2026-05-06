package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests for [KSafeMemoryPolicy] enum.
 */
class KSafeMemoryPolicyTest {

    // ============ ENUM VALUES ============

    /** Verifies enum has exactly 4 values: PLAIN_TEXT, ENCRYPTED, ENCRYPTED_WITH_TIMED_CACHE, LAZY_PLAIN_TEXT */
    @Test
    fun memoryPolicy_hasCorrectNumberOfValues() {
        val values = KSafeMemoryPolicy.entries
        assertEquals(4, values.size, "KSafeMemoryPolicy should have exactly 4 values")
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

    /** Verifies ENCRYPTED_WITH_TIMED_CACHE value exists in enum */
    @Test
    fun memoryPolicy_containsEncryptedWithTimedCache() {
        val values = KSafeMemoryPolicy.entries
        assertTrue(values.contains(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE))
    }

    /** Verifies LAZY_PLAIN_TEXT value exists in enum */
    @Test
    fun memoryPolicy_containsLazyPlainText() {
        val values = KSafeMemoryPolicy.entries
        assertTrue(values.contains(KSafeMemoryPolicy.LAZY_PLAIN_TEXT))
    }

    // ============ ORDINAL ORDER ============

    /** Verifies ordinal values: PLAIN_TEXT=0, ENCRYPTED=1, ENCRYPTED_WITH_TIMED_CACHE=2, LAZY_PLAIN_TEXT=3 */
    @Test
    fun memoryPolicy_ordinalOrder() {
        // Verify the order as defined in the enum
        assertEquals(0, KSafeMemoryPolicy.PLAIN_TEXT.ordinal)
        assertEquals(1, KSafeMemoryPolicy.ENCRYPTED.ordinal)
        assertEquals(2, KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE.ordinal)
        assertEquals(3, KSafeMemoryPolicy.LAZY_PLAIN_TEXT.ordinal)
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

    /** Verifies ENCRYPTED_WITH_TIMED_CACHE.name returns "ENCRYPTED_WITH_TIMED_CACHE" */
    @Test
    fun memoryPolicy_encryptedWithTimedCache_name() {
        assertEquals("ENCRYPTED_WITH_TIMED_CACHE", KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE.name)
    }

    /** Verifies LAZY_PLAIN_TEXT.name returns "LAZY_PLAIN_TEXT" */
    @Test
    fun memoryPolicy_lazyPlainText_name() {
        assertEquals("LAZY_PLAIN_TEXT", KSafeMemoryPolicy.LAZY_PLAIN_TEXT.name)
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

    /** Verifies valueOf("ENCRYPTED_WITH_TIMED_CACHE") returns correct enum value */
    @Test
    fun memoryPolicy_valueOf_encryptedWithTimedCache() {
        val policy = KSafeMemoryPolicy.valueOf("ENCRYPTED_WITH_TIMED_CACHE")
        assertEquals(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE, policy)
    }

    /** Verifies valueOf("LAZY_PLAIN_TEXT") returns correct enum value */
    @Test
    fun memoryPolicy_valueOf_lazyPlainText() {
        val policy = KSafeMemoryPolicy.valueOf("LAZY_PLAIN_TEXT")
        assertEquals(KSafeMemoryPolicy.LAZY_PLAIN_TEXT, policy)
    }

    // ============ USE CASES ============

    /** Verifies when expression covers all enum values exhaustively */
    @Test
    fun memoryPolicy_whenExpression_exhaustive() {
        KSafeMemoryPolicy.entries.forEach { policy ->
            val description = when (policy) {
                KSafeMemoryPolicy.PLAIN_TEXT -> "Plain text in memory for performance"
                KSafeMemoryPolicy.ENCRYPTED -> "Encrypted in memory for security"
                KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE -> "Encrypted with short-lived plaintext cache"
                KSafeMemoryPolicy.LAZY_PLAIN_TEXT -> "Encrypted at rest, lazily decrypted into a permanent plaintext side cache"
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
        assertEquals(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE, KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)
        assertEquals(KSafeMemoryPolicy.LAZY_PLAIN_TEXT, KSafeMemoryPolicy.LAZY_PLAIN_TEXT)
        assertTrue(KSafeMemoryPolicy.PLAIN_TEXT != KSafeMemoryPolicy.ENCRYPTED)
        assertTrue(KSafeMemoryPolicy.ENCRYPTED != KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)
        assertTrue(KSafeMemoryPolicy.PLAIN_TEXT != KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)
        assertTrue(KSafeMemoryPolicy.LAZY_PLAIN_TEXT != KSafeMemoryPolicy.PLAIN_TEXT)
        assertTrue(KSafeMemoryPolicy.LAZY_PLAIN_TEXT != KSafeMemoryPolicy.ENCRYPTED)
        assertTrue(KSafeMemoryPolicy.LAZY_PLAIN_TEXT != KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE)
    }
}
