package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: KSafeConfig defaults, typed AES key sizes, and data-class behavior.
 */
class KSafeConfigTest {

    @Test
    fun defaultConfig_hasCorrectDefaults() {
        val config = KSafeConfig()

        assertEquals(
            KSafeAesKeySize.BITS_256,
            config.aesKeySize,
            "Default AES key size should be 256 bits",
        )
        assertFalse(config.requireUnlockedDevice, "Default requireUnlockedDevice should be false")
        assertEquals(3, config.keyRotationRetryAttempts)
    }

    @Test
    fun aesKeySize_128_hasExpectedDimensions() {
        val config = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_128)
        assertEquals(128, config.aesKeySize.bits)
        assertEquals(16, config.aesKeySize.bytes)
    }

    @Test
    fun aesKeySize_256_hasExpectedDimensions() {
        val config = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_256)
        assertEquals(256, config.aesKeySize.bits)
        assertEquals(32, config.aesKeySize.bytes)
    }

    @Test
    fun keyRotationRetryAttempts_zeroAndPositive_areValid() {
        assertEquals(0, KSafeConfig(keyRotationRetryAttempts = 0).keyRotationRetryAttempts)
        assertEquals(7, KSafeConfig(keyRotationRetryAttempts = 7).keyRotationRetryAttempts)
    }

    @Test
    fun keyRotationRetryAttempts_negative_throwsException() {
        assertFailsWith<IllegalArgumentException> {
            KSafeConfig(keyRotationRetryAttempts = -1)
        }
    }

    @Test
    fun config_equality_works() {
        val config1 = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_256)
        val config2 = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_256)
        val config3 = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_128)

        assertEquals(config1, config2, "Same configs should be equal")
        assertFalse(config1 == config3, "Different configs should not be equal")
    }

    @Test
    fun config_copy_works() {
        val original = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_256)
        val copied = original.copy(aesKeySize = KSafeAesKeySize.BITS_128)

        assertEquals(KSafeAesKeySize.BITS_256, original.aesKeySize)
        assertEquals(KSafeAesKeySize.BITS_128, copied.aesKeySize)
        assertEquals(original.requireUnlockedDevice, copied.requireUnlockedDevice)
        assertEquals(original.keyRotationRetryAttempts, copied.keyRotationRetryAttempts)
    }

    // ---- the pre-3.1.0 keySize surface, kept until 4.0.0 -------------------------------

    @Suppress("DEPRECATION")
    @Test
    fun deprecatedKeySize_stillConstructsAndReads() {
        assertEquals(KSafeAesKeySize.BITS_128, KSafeConfig(keySize = 128).aesKeySize)
        assertEquals(KSafeAesKeySize.BITS_256, KSafeConfig(keySize = 256).aesKeySize)
        assertEquals(128, KSafeConfig(keySize = 128).keySize)
        assertEquals(256, KSafeConfig().keySize)
    }

    @Suppress("DEPRECATION")
    @Test
    fun deprecatedKeySize_acceptsTheOldPositionalSignature() {
        val config = KSafeConfig(128, true, KSafeDefaults.json, "ns", KSafeKeyRotationPolicy.Never)
        assertEquals(KSafeAesKeySize.BITS_128, config.aesKeySize)
        assertEquals("ns", config.appNamespace)
        assertTrue(config.requireUnlockedDevice)
    }

    @Suppress("DEPRECATION")
    @Test
    fun deprecatedKeySize_rejectsAnUnsupportedBitCountWithTheOldMessage() {
        val error = assertFailsWith<IllegalArgumentException> { KSafeConfig(keySize = 512) }
        assertEquals("keySize must be 128 or 256 bits. Got: 512", error.message)
    }

    @Suppress("DEPRECATION")
    @Test
    fun deprecatedKeySize_stillCopies_andLeavesTheGeneratedCopyReachable() {
        val base = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_256, keyRotationRetryAttempts = 7)

        val viaInt = base.copy(keySize = 128)
        assertEquals(KSafeAesKeySize.BITS_128, viaInt.aesKeySize)
        assertEquals(7, viaInt.keyRotationRetryAttempts, "unrelated fields must carry over")

        // No argument, and any non-keySize argument, must still reach the generated copy.
        assertEquals(base, base.copy())
        assertEquals(KSafeAesKeySize.BITS_128, base.copy(aesKeySize = KSafeAesKeySize.BITS_128).aesKeySize)
    }
}
