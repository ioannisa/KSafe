package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in the key-rotation generation plumbing: metadata's `g` field is absent for generation 1, so
 * an un-rotated store's payload stays byte-identical to pre-rotation releases and never churns, and
 * round-trips for rotated entries. Generation 1 is the un-suffixed base alias every existing key
 * already uses (zero migration); later generations get a deterministic `.gN` suffix.
 */
class KSafeKeyGenerationTest {

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
        // Generation records are plaintext: a fabricated Int.MAX_VALUE would drive the sweep loops
        // for billions of vault round-trips and wrap the rotation increment negative.
        val max = KeySafeMetadataManager.MAX_KEY_GENERATION
        assertEquals(max, KeySafeMetadataManager.parseKeyGeneration("""{"g":2147483647}"""))
        assertEquals(max, KeySafeMetadataManager.parseKeyGeneration("""{"g":${max + 1}}"""))
        assertEquals(max, KeySafeMetadataManager.parseKeyGeneration("""{"g":$max}"""), "the bound itself is legal")
        assertEquals(max - 1, KeySafeMetadataManager.parseKeyGeneration("""{"g":${max - 1}}"""))
    }

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
        // The refusal must not read as missing-key or transient: the sweep reaps entries on the
        // former, destroying a future-format entry an upgrade could read; reads spin on the latter.
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

    @Test
    fun keyGenerationState_rotationLifecycle_distinguishes30_completed_andInProgress() {
        val legacy30 = """{"g":2,"ts":123}"""
        assertEquals(null, KeySafeMetadataManager.parseKeyRotationLifecycle(legacy30))
        assertFalse(KeySafeMetadataManager.hasKeyRotationLifecycle(legacy30))
        assertTrue(KeySafeMetadataManager.isLegacy30KeyGenerationState(legacy30))
        assertFalse(KeySafeMetadataManager.parseKeyRotationInProgress(legacy30))

        val active = KeySafeMetadataManager.buildKeyGenerationState(
            generation = 2,
            timestampMillis = 123L,
            rotationInProgress = true,
        )
        assertEquals("""{"g":2,"ts":123,"r":1}""", active)
        assertTrue(KeySafeMetadataManager.hasKeyRotationLifecycle(active))
        assertFalse(KeySafeMetadataManager.isLegacy30KeyGenerationState(active))
        assertEquals(1, KeySafeMetadataManager.parseKeyRotationLifecycle(active))
        assertTrue(KeySafeMetadataManager.parseKeyRotationInProgress(active))

        val completed = KeySafeMetadataManager.buildKeyGenerationState(
            generation = 2,
            timestampMillis = 123L,
        )
        assertEquals("""{"g":2,"ts":123,"r":0}""", completed)
        assertTrue(KeySafeMetadataManager.hasKeyRotationLifecycle(completed))
        assertFalse(KeySafeMetadataManager.isLegacy30KeyGenerationState(completed))
        assertEquals(0, KeySafeMetadataManager.parseKeyRotationLifecycle(completed))
        assertFalse(KeySafeMetadataManager.parseKeyRotationInProgress(completed))

        val retryPending = KeySafeMetadataManager.buildKeyGenerationState(
            generation = 2,
            timestampMillis = 123L,
            retryAttemptsRemaining = 3,
        )
        assertEquals("""{"g":2,"ts":123,"r":0,"rp":3}""", retryPending)
        assertTrue(KeySafeMetadataManager.hasKeyRotationRetryPending(retryPending))
        assertEquals(3, KeySafeMetadataManager.parseKeyRotationRetryAttempts(retryPending))
        assertTrue(KeySafeMetadataManager.hasSupportedKeyRotationRetryState(retryPending))
        assertFalse(KeySafeMetadataManager.hasKeyRotationRetryPending(completed))
        assertEquals(null, KeySafeMetadataManager.parseKeyRotationRetryAttempts(completed))
        assertTrue(
            KeySafeMetadataManager.hasKeyRotationRetryPending(
                """{"g":2,"ts":123,"r":0,"rp":"future"}"""
            )
        )
        assertEquals(
            null,
            KeySafeMetadataManager.parseKeyRotationRetryAttempts(
                """{"g":2,"ts":123,"r":0,"rp":"future"}"""
            ),
        )
        assertFalse(
            KeySafeMetadataManager.hasSupportedKeyRotationRetryState(
                """{"g":2,"ts":123,"r":0,"rp":"future"}"""
            )
        )
        assertFalse(
            KeySafeMetadataManager.hasSupportedKeyRotationRetryState(
                """{"g":2,"ts":123,"r":0,"rp":0}"""
            )
        )
        assertTrue(
            KeySafeMetadataManager.hasSupportedKeyRotationRetryState(
                """{"g":2,"ts":123,"r":1,"rp":0}"""
            ),
            "rp:0 is the crash-recovery state of the final claimed attempt",
        )

        assertEquals(2, KeySafeMetadataManager.parseKeyRotationLifecycle("""{"g":2,"r":2}"""))
        assertTrue(KeySafeMetadataManager.hasKeyRotationLifecycle("""{"g":2,"r":"future"}"""))
        assertEquals(
            null,
            KeySafeMetadataManager.parseKeyRotationLifecycle("""{"g":2,"r":"future"}"""),
        )
        assertFalse(KeySafeMetadataManager.isLegacy30KeyGenerationState("garbage"))
        assertFalse(KeySafeMetadataManager.isLegacy30KeyGenerationState("""{"g":2}"""))
        assertFalse(KeySafeMetadataManager.isLegacy30KeyGenerationState("""{"g":10001,"ts":123}"""))
        assertFalse(
            KeySafeMetadataManager.isLegacy30KeyGenerationState(
                """{"g":2,"ts":123,"future":true}"""
            )
        )
        assertFalse(KeySafeMetadataManager.parseKeyRotationInProgress(null))
        assertFalse(KeySafeMetadataManager.parseKeyRotationInProgress("garbage"))
        assertFalse(
            KeySafeMetadataManager.parseKeyRotationInProgress("""{"g":2,"ts":123,"r":0}""")
        )
    }

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

    @Test
    fun reservedNamespaceKeys_areRejectedForWrite_readsUnaffected() {
        // The `__ksafe_` internal namespace and the `encrypted_` legacy/cache prefix must not be
        // writable through the public API.
        assertTrue(KeySafeMetadataManager.isReservedNamespaceKey("__ksafe_keygen__"))
        assertTrue(KeySafeMetadataManager.isReservedNamespaceKey("__ksafe_value_x"))
        assertTrue(KeySafeMetadataManager.isReservedNamespaceKey("__ksafe_anything"))
        assertTrue(KeySafeMetadataManager.isReservedNamespaceKey("encrypted_foo"), "collision key")
        assertFalse(KeySafeMetadataManager.isReservedNamespaceKey("token"))
        assertFalse(KeySafeMetadataManager.isReservedNamespaceKey("ksafe_theme"), "single-underscore is a user key")
        assertFalse(KeySafeMetadataManager.isReservedNamespaceKey("ksafe_secret_db"), "getOrCreateSecret slot")
        assertFalse(KeySafeMetadataManager.isReservedNamespaceKey("my_encrypted_note"), "prefix must be at the START")

        // isReservedUserKey is the exact master-sentinel predicate the sweep relies on.
        assertTrue(KeySafeMetadataManager.isReservedUserKey("__ksafe_master__"))
        assertFalse(KeySafeMetadataManager.isReservedUserKey("__ksafe_master__x"), "sweep predicate is exact")
        assertFalse(KeySafeMetadataManager.isReservedUserKey("__ksafe_keygen__"), "not a master sentinel")
    }
}
