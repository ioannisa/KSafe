package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.secureRandomBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Coverage for the `appleMain` actual of [secureRandomBytes]
 * (`KSafeSecureRandom.apple.kt`), which backs **AES-256 master-key generation**
 * on iOS and macOS (`AppleKeychainEncryption.getOrCreateKeychainKeySE` /
 * `getOrCreateKeychainKeyPlain`).
 *
 * The Apple actual must draw from `SecRandomCopyBytes` (the Security framework
 * CSPRNG) — `kotlin.random.Random.nextBytes(size)` is NOT a CSPRNG and must
 * never back key generation on this security-critical path.
 *
 * macOS runs the identical `appleMain` actual that iOS does, so exercising it
 * here covers both. These are statistical sanity checks, not a crypto-grade
 * randomness battery — they catch the failure modes that actually matter
 * (constant output, zero buffer, repeated output, wrong length, non-positive
 * size) without flaking.
 */
class MacosSecureRandomTest {

    @Test
    fun returnsRequestedLength() {
        assertEquals(1, secureRandomBytes(1).size)
        assertEquals(12, secureRandomBytes(12).size)   // GCM-nonce-sized
        assertEquals(32, secureRandomBytes(32).size)   // AES-256 key-sized
        assertEquals(64, secureRandomBytes(64).size)
    }

    @Test
    fun rejectsNonPositiveSize() {
        assertFailsWith<IllegalArgumentException> { secureRandomBytes(0) }
        assertFailsWith<IllegalArgumentException> { secureRandomBytes(-1) }
    }

    @Test
    fun doesNotReturnAllZeros() {
        // A no-op'd buffer or failed CSPRNG call yields all zeros; a real
        // CSPRNG does so with probability 2^-256.
        val bytes = secureRandomBytes(32)
        assertFalse(bytes.all { it == 0.toByte() }, "secureRandomBytes returned an all-zero buffer")
    }

    @Test
    fun successiveCallsDiffer() {
        // Two 32-byte draws colliding from a real CSPRNG is a 2^-256 event.
        val a = secureRandomBytes(32)
        val b = secureRandomBytes(32)
        assertFalse(a.contentEquals(b), "two secureRandomBytes(32) draws were identical")
    }

    @Test
    fun outputSpansAWideByteRange() {
        // 4 KiB of CSPRNG output covers nearly all 256 byte values; 200/256 is
        // far above any degenerate source yet low enough not to flake.
        val bytes = secureRandomBytes(4096)
        val distinct = bytes.toSet().size
        assertTrue(distinct > 200, "only $distinct distinct byte values in 4 KiB — suspiciously low entropy")
    }
}
