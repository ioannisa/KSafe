package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in the key-rotation generation plumbing (3.0.0):
 * - metadata `g` field: absent for generation 1 (byte-identical payload to pre-rotation
 *   releases, so un-rotated stores never churn), present and round-tripping for rotated entries;
 * - alias derivation: generation 1 IS the un-suffixed base alias every existing key uses
 *   (zero-migration invariant), later generations get a deterministic `.gN` suffix.
 */
class KSafeKeyGenerationTest {

    // ---- metadata `g` field --------------------------------------------------------------

    @Test
    fun buildMetadataJson_generation1_isByteIdenticalToPreRotationPayload() {
        val withoutParam = KeySafeMetadataManager.buildMetadataJson(
            protection = KSafeProtection.DEFAULT,
            accessPolicy = null,
        )
        val withExplicitGen1 = KeySafeMetadataManager.buildMetadataJson(
            protection = KSafeProtection.DEFAULT,
            accessPolicy = null,
            keyGeneration = 1,
        )
        assertEquals(withoutParam, withExplicitGen1)
        assertTrue("\"g\"" !in withExplicitGen1, "generation 1 must not serialize a g field")
    }

    @Test
    fun buildMetadataJson_rotatedGeneration_roundTrips() {
        val meta = KeySafeMetadataManager.buildMetadataJson(
            protection = KSafeProtection.DEFAULT,
            accessPolicy = null,
            keyGeneration = 3,
        )
        assertTrue("\"g\":3" in meta, "a rotated generation must be recorded in the payload")
        assertEquals(3, KeySafeMetadataManager.parseKeyGeneration(meta))
        // The other parsers must be unaffected by the extra field.
        assertEquals(KSafeProtection.DEFAULT, KeySafeMetadataManager.parseProtection(meta))
        assertEquals(
            KeySafeMetadataManager.ENVELOPE_VERSION_LATEST,
            KeySafeMetadataManager.parseEnvelopeVersion(meta),
        )
    }

    @Test
    fun parseKeyGeneration_defaultsTo1_forEverythingPreRotation() {
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration(null))
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration("DEFAULT"), "legacy literal")
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration("HARDWARE_ISOLATED"), "legacy literal")
        assertEquals(
            1,
            KeySafeMetadataManager.parseKeyGeneration("""{"v":2,"p":"DEFAULT"}"""),
            "a v2 payload without g is the base generation",
        )
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration("not json at all"))
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration("""{"v":2,"p":"DEFAULT","g":0}"""),
            "a nonsensical generation is coerced to the base")
        assertEquals(1, KeySafeMetadataManager.parseKeyGeneration("""{"v":2,"p":"DEFAULT","g":"x"}"""))
    }

    @Test
    fun parseKeyGeneration_readsTheRotatedGeneration() {
        assertEquals(4, KeySafeMetadataManager.parseKeyGeneration("""{"v":2,"p":"DEFAULT","g":4}"""))
        assertEquals(2, KeySafeMetadataManager.parseKeyGeneration("""{"g":2}"""), "the keygen state entry's own payload")
    }

    @Test
    fun parseKeyGeneration_clampsFabricatedHugeValues() {
        // Generation records are plaintext routing metadata: an attacker-fabricated
        // Int.MAX_VALUE would drive the per-generation sweep loops for billions of vault
        // round-trips and wrap the rotation increment negative. Nothing legitimate ever
        // writes above the bound, so clamping changes no honest store.
        val max = KeySafeMetadataManager.MAX_KEY_GENERATION
        assertEquals(max, KeySafeMetadataManager.parseKeyGeneration("""{"g":2147483647}"""))
        assertEquals(max, KeySafeMetadataManager.parseKeyGeneration("""{"g":${max + 1}}"""))
        assertEquals(max, KeySafeMetadataManager.parseKeyGeneration("""{"g":$max}"""), "the bound itself is legal")
        assertEquals(max - 1, KeySafeMetadataManager.parseKeyGeneration("""{"g":${max - 1}}"""))
    }

    // ---- envelope-version fail-closed gate ------------------------------------------------

    @Test
    fun checkKnownEnvelopeVersion_acceptsEveryKnownVersion_failsClosedOnFuture() {
        for (v in 1..KeySafeMetadataManager.ENVELOPE_VERSION_MAX_KNOWN) {
            KeySafeMetadataManager.checkKnownEnvelopeVersion(v, "k") // must not throw
        }
        val e = assertFailsWith<IllegalStateException> {
            KeySafeMetadataManager.checkKnownEnvelopeVersion(
                KeySafeMetadataManager.ENVELOPE_VERSION_MAX_KNOWN + 1, "k",
            )
        }
        // The refusal must never read as a MISSING-KEY or TRANSIENT failure: the orphan sweep
        // reaps entries on the former (destroying a future-format entry an upgrade could read)
        // and read paths spin awaiting unlock on the latter.
        val msg = e.message!!.lowercase()
        assertFalse("no encryption key found" in msg)
        assertFalse("key not found" in msg)
        assertFalse("web key missing" in msg)
        assertFalse("vault unavailable" in msg)
        assertFalse("device is locked" in msg)
        assertFalse("keystore" in msg)
        assertFalse("keychain" in msg)
    }

    @Test
    fun parseKeyGenerationTimestamp_readsTheBirth_orNullWhenUnstamped() {
        // The state payload the consumer persists for SetKeyGeneration.
        assertEquals(1234567890123L, KeySafeMetadataManager.parseKeyGenerationTimestamp("""{"g":2,"ts":1234567890123}"""))
        assertEquals(null, KeySafeMetadataManager.parseKeyGenerationTimestamp(null))
        assertEquals(null, KeySafeMetadataManager.parseKeyGenerationTimestamp("""{"g":2}"""), "pre-policy state has no birth")
        assertEquals(null, KeySafeMetadataManager.parseKeyGenerationTimestamp("garbage"))
    }

    // ---- alias derivation ----------------------------------------------------------------

    @Test
    fun aliasWithGeneration_generation1_isTheUnsuffixedBaseAlias() {
        // The zero-migration invariant: every pre-rotation key keeps its exact alias.
        assertEquals("master", KSafeCore.aliasWithGeneration("master", 1))
        assertEquals("master", KSafeCore.aliasWithGeneration("master", 0), "defensive: below-base clamps to base")
    }

    @Test
    fun aliasWithGeneration_rotatedGenerations_suffixDeterministically() {
        assertEquals("master.g2", KSafeCore.aliasWithGeneration("master", 2))
        assertEquals("ks.vault.token.g7", KSafeCore.aliasWithGeneration("ks.vault.token", 7))
    }

    // ---- reserved-namespace write guard ----------------------------------------

    @Test
    fun reservedNamespaceKeys_areRejectedForWrite_readsUnaffected() {
        // `__ksafe_` internal namespace (incl. the rotation keygen entry) and the
        // `encrypted_` legacy/cache prefix must not be writable through the public API.
        assertTrue(KeySafeMetadataManager.isReservedNamespaceKey("__ksafe_keygen__"))
        assertTrue(KeySafeMetadataManager.isReservedNamespaceKey("__ksafe_value_x"))
        assertTrue(KeySafeMetadataManager.isReservedNamespaceKey("__ksafe_anything"))
        assertTrue(KeySafeMetadataManager.isReservedNamespaceKey("encrypted_foo"), "collision key")
        // Ordinary keys — including a single-underscore 'ksafe_' and the secret slot prefix —
        // stay writable.
        assertFalse(KeySafeMetadataManager.isReservedNamespaceKey("token"))
        assertFalse(KeySafeMetadataManager.isReservedNamespaceKey("ksafe_theme"), "single-underscore is a user key")
        assertFalse(KeySafeMetadataManager.isReservedNamespaceKey("ksafe_secret_db"), "getOrCreateSecret slot")
        assertFalse(KeySafeMetadataManager.isReservedNamespaceKey("my_encrypted_note"), "prefix must be at the START")

        // isReservedUserKey (the exact master-sentinel predicate the sweep relies on) stays EXACT.
        assertTrue(KeySafeMetadataManager.isReservedUserKey("__ksafe_master__"))
        assertFalse(KeySafeMetadataManager.isReservedUserKey("__ksafe_master__x"), "sweep predicate is exact")
        assertFalse(KeySafeMetadataManager.isReservedUserKey("__ksafe_keygen__"), "not a master sentinel")
    }
}
