package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: KSafeMemoryPolicy enum values, ordinals, names, and valueOf lookups.
 */
class KSafeMemoryPolicyTest {

    @Test
    fun memoryPolicy_hasCorrectNumberOfValues() {
        val values = KSafeMemoryPolicy.entries
        assertEquals(4, values.size, "KSafeMemoryPolicy should have exactly 4 values")
    }

    @Test
    fun memoryPolicy_containsPlainText() {
        val values = KSafeMemoryPolicy.entries
        assertTrue(values.contains(KSafeMemoryPolicy.PLAIN_TEXT))
    }

    @Test
    fun memoryPolicy_containsEncrypted() {
        val values = KSafeMemoryPolicy.entries
        assertTrue(values.contains(KSafeMemoryPolicy.ENCRYPTED))
    }

    @Test
    fun memoryPolicy_containsEncryptedWithTimedCache() {
        val values = KSafeMemoryPolicy.entries
        assertTrue(values.contains(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE))
    }

    @Test
    fun memoryPolicy_containsLazyPlainText() {
        val values = KSafeMemoryPolicy.entries
        assertTrue(values.contains(KSafeMemoryPolicy.LAZY_PLAIN_TEXT))
    }

    @Test
    fun memoryPolicy_ordinalOrder() {
        assertEquals(0, KSafeMemoryPolicy.PLAIN_TEXT.ordinal)
        assertEquals(1, KSafeMemoryPolicy.ENCRYPTED.ordinal)
        assertEquals(2, KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE.ordinal)
        assertEquals(3, KSafeMemoryPolicy.LAZY_PLAIN_TEXT.ordinal)
    }

    @Test
    fun memoryPolicy_plainText_name() {
        assertEquals("PLAIN_TEXT", KSafeMemoryPolicy.PLAIN_TEXT.name)
    }

    @Test
    fun memoryPolicy_encrypted_name() {
        assertEquals("ENCRYPTED", KSafeMemoryPolicy.ENCRYPTED.name)
    }

    @Test
    fun memoryPolicy_encryptedWithTimedCache_name() {
        assertEquals("ENCRYPTED_WITH_TIMED_CACHE", KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE.name)
    }

    @Test
    fun memoryPolicy_lazyPlainText_name() {
        assertEquals("LAZY_PLAIN_TEXT", KSafeMemoryPolicy.LAZY_PLAIN_TEXT.name)
    }

    @Test
    fun memoryPolicy_valueOf_plainText() {
        val policy = KSafeMemoryPolicy.valueOf("PLAIN_TEXT")
        assertEquals(KSafeMemoryPolicy.PLAIN_TEXT, policy)
    }

    @Test
    fun memoryPolicy_valueOf_encrypted() {
        val policy = KSafeMemoryPolicy.valueOf("ENCRYPTED")
        assertEquals(KSafeMemoryPolicy.ENCRYPTED, policy)
    }

    @Test
    fun memoryPolicy_valueOf_encryptedWithTimedCache() {
        val policy = KSafeMemoryPolicy.valueOf("ENCRYPTED_WITH_TIMED_CACHE")
        assertEquals(KSafeMemoryPolicy.ENCRYPTED_WITH_TIMED_CACHE, policy)
    }

    @Test
    fun memoryPolicy_valueOf_lazyPlainText() {
        val policy = KSafeMemoryPolicy.valueOf("LAZY_PLAIN_TEXT")
        assertEquals(KSafeMemoryPolicy.LAZY_PLAIN_TEXT, policy)
    }

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

    @Test
    fun memoryPolicy_comparison() {
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
