package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.canonicalNamespaceToken
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: [canonicalNamespaceToken] is injective for distinct configured ids — a lossy
 * sanitization (`a/b` vs `a?b` → both `a_b`) or a 120-char truncation must NOT collapse two
 * logical apps onto one data/key identity, or they silently share slots and key custody and
 * can read, overwrite, or `clearAll()` each other. Deliberate equivalences (whitespace
 * padding, leading dots) still agree, and clean tokens pass through unchanged so documented
 * usage needs no migration.
 */
class NamespaceTokenTest {

    @Test
    fun cleanTokens_passThroughUnchanged() {
        for (raw in listOf("foo", "com.example.App", "a_b", "my-app", "A1._-z")) {
            assertEquals(raw, canonicalNamespaceToken(raw), "clean token must be unchanged")
        }
    }

    @Test
    fun deliberateEquivalences_agreeWithoutADigest() {
        // Whitespace padding and leading dots are cosmetic — one identity, no digest.
        for (raw in listOf(" foo ", ".foo", "..foo", " .foo ")) {
            assertEquals("foo", canonicalNamespaceToken(raw), "'$raw' must canonicalize to plain 'foo'")
        }
    }

    @Test
    fun cancelledOutTokens_meanNoNamespace() {
        for (raw in listOf(null, "", "   ", "...", " .. ")) {
            assertNull(canonicalNamespaceToken(raw), "'$raw' must cancel out entirely")
        }
    }

    @Test
    fun lossyCollisionPair_staysDistinct() {
        val slash = canonicalNamespaceToken("a/b")!!
        val question = canonicalNamespaceToken("a?b")!!
        assertNotEquals(
            slash, question,
            "'a/b' and 'a?b' are DIFFERENT configured ids and must not share one namespace token",
        )
        // Both stay recognizable and store-safe.
        assertTrue(slash.startsWith("a_b"), "sanitized part must stay human-readable: '$slash'")
        assertTrue(slash.matches(Regex("[A-Za-z0-9._-]+")), "token must be store-safe: '$slash'")
        assertTrue(question.matches(Regex("[A-Za-z0-9._-]+")), "token must be store-safe: '$question'")
    }

    @Test
    fun longIdsSharingA120CharPrefix_stayDistinct() {
        val prefix = "x".repeat(120)
        val a = canonicalNamespaceToken(prefix + "A")!!
        val b = canonicalNamespaceToken(prefix + "B")!!
        assertNotEquals(a, b, "two ids sharing a 120-char prefix must not collapse to one token")
    }

    @Test
    fun lossyToken_isDeterministicAcrossCalls() {
        assertEquals(canonicalNamespaceToken("a/b"), canonicalNamespaceToken("a/b"))
        // Equivalence-normalization applies before the digest, so padding doesn't fork identities.
        assertEquals(canonicalNamespaceToken("a/b"), canonicalNamespaceToken(" a/b "))
    }
}
