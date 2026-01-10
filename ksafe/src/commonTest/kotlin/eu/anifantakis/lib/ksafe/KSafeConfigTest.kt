package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/**
 * Tests for [KSafeConfig] validation and defaults.
 *
 * Note: Biometric authentication is a standalone helper via `verifyBiometric()` and
 * `verifyBiometricDirect()`. See KSafe API for biometric usage.
 */
class KSafeConfigTest {

    // ============ DEFAULT VALUES ============

    /** Verifies default constructor sets AES-256 and 30 seconds auth validity */
    @Test
    fun defaultConfig_hasCorrectDefaults() {
        val config = KSafeConfig()

        assertEquals(256, config.keySize, "Default keySize should be 256")
        assertEquals(30, config.androidAuthValiditySeconds, "Default androidAuthValiditySeconds should be 30")
    }

    // ============ KEY SIZE VALIDATION ============

    /** Verifies AES-128 key size is accepted */
    @Test
    fun keySize_128_isValid() {
        val config = KSafeConfig(keySize = 128)
        assertEquals(128, config.keySize)
    }

    /** Verifies AES-256 key size is accepted */
    @Test
    fun keySize_256_isValid() {
        val config = KSafeConfig(keySize = 256)
        assertEquals(256, config.keySize)
    }

    /** Verifies invalid key sizes (64, 192, 512) throw IllegalArgumentException */
    @Test
    fun keySize_invalid_throwsException() {
        assertFailsWith<IllegalArgumentException> {
            KSafeConfig(keySize = 64)
        }

        assertFailsWith<IllegalArgumentException> {
            KSafeConfig(keySize = 192)
        }

        assertFailsWith<IllegalArgumentException> {
            KSafeConfig(keySize = 512)
        }
    }

    // ============ ANDROID AUTH VALIDITY ============

    /** Verifies custom auth validity seconds is accepted */
    @Test
    fun androidAuthValiditySeconds_customValue_isValid() {
        val config = KSafeConfig(androidAuthValiditySeconds = 60)
        assertEquals(60, config.androidAuthValiditySeconds)
    }

    /** Verifies zero auth validity throws IllegalArgumentException */
    @Test
    fun androidAuthValiditySeconds_zeroValue_throwsException() {
        assertFailsWith<IllegalArgumentException> {
            KSafeConfig(androidAuthValiditySeconds = 0)
        }
    }

    /** Verifies negative auth validity throws IllegalArgumentException */
    @Test
    fun androidAuthValiditySeconds_negativeValue_throwsException() {
        assertFailsWith<IllegalArgumentException> {
            KSafeConfig(androidAuthValiditySeconds = -1)
        }
    }

    // ============ COMBINED CONFIGURATIONS ============

    /** Verifies combining custom key size with custom auth validity works */
    @Test
    fun customKeySize_withCustomValidity_isValid() {
        val config = KSafeConfig(
            keySize = 128,
            androidAuthValiditySeconds = 45
        )

        assertEquals(128, config.keySize)
        assertEquals(45, config.androidAuthValiditySeconds)
    }

    /** Verifies default constructor creates valid config without exception */
    @Test
    fun allDefaults_createValidConfig() {
        // Just ensure no exception is thrown
        val config = KSafeConfig()
        assertEquals(256, config.keySize)
        assertEquals(30, config.androidAuthValiditySeconds)
    }

    // ============ DATA CLASS BEHAVIOR ============

    /** Verifies data class equality based on field values */
    @Test
    fun config_equality_works() {
        val config1 = KSafeConfig(keySize = 256, androidAuthValiditySeconds = 30)
        val config2 = KSafeConfig(keySize = 256, androidAuthValiditySeconds = 30)
        val config3 = KSafeConfig(keySize = 128, androidAuthValiditySeconds = 30)

        assertEquals(config1, config2, "Same configs should be equal")
        assertFalse(config1 == config3, "Different configs should not be equal")
    }

    /** Verifies copy() creates modified instance without mutating original */
    @Test
    fun config_copy_works() {
        val original = KSafeConfig(keySize = 256, androidAuthValiditySeconds = 30)
        val copied = original.copy(androidAuthValiditySeconds = 60)

        assertEquals(30, original.androidAuthValiditySeconds)
        assertEquals(60, copied.androidAuthValiditySeconds)
        assertEquals(original.keySize, copied.keySize)
    }
}
