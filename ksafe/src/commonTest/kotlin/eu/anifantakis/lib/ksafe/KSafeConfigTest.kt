package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/**
 * Locks in: KSafeConfig defaults, key-size and auth-validity validation, and data-class behavior.
 */
class KSafeConfigTest {

    @Test
    fun defaultConfig_hasCorrectDefaults() {
        val config = KSafeConfig()

        assertEquals(256, config.keySize, "Default keySize should be 256")
        assertEquals(30, config.androidAuthValiditySeconds, "Default androidAuthValiditySeconds should be 30")
    }

    @Test
    fun keySize_128_isValid() {
        val config = KSafeConfig(keySize = 128)
        assertEquals(128, config.keySize)
    }

    @Test
    fun keySize_256_isValid() {
        val config = KSafeConfig(keySize = 256)
        assertEquals(256, config.keySize)
    }

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

    @Test
    fun androidAuthValiditySeconds_customValue_isValid() {
        val config = KSafeConfig(androidAuthValiditySeconds = 60)
        assertEquals(60, config.androidAuthValiditySeconds)
    }

    @Test
    fun androidAuthValiditySeconds_zeroValue_throwsException() {
        assertFailsWith<IllegalArgumentException> {
            KSafeConfig(androidAuthValiditySeconds = 0)
        }
    }

    @Test
    fun androidAuthValiditySeconds_negativeValue_throwsException() {
        assertFailsWith<IllegalArgumentException> {
            KSafeConfig(androidAuthValiditySeconds = -1)
        }
    }

    @Test
    fun customKeySize_withCustomValidity_isValid() {
        val config = KSafeConfig(
            keySize = 128,
            androidAuthValiditySeconds = 45
        )

        assertEquals(128, config.keySize)
        assertEquals(45, config.androidAuthValiditySeconds)
    }

    @Test
    fun allDefaults_createValidConfig() {
        val config = KSafeConfig()
        assertEquals(256, config.keySize)
        assertEquals(30, config.androidAuthValiditySeconds)
    }

    @Test
    fun config_equality_works() {
        val config1 = KSafeConfig(keySize = 256, androidAuthValiditySeconds = 30)
        val config2 = KSafeConfig(keySize = 256, androidAuthValiditySeconds = 30)
        val config3 = KSafeConfig(keySize = 128, androidAuthValiditySeconds = 30)

        assertEquals(config1, config2, "Same configs should be equal")
        assertFalse(config1 == config3, "Different configs should not be equal")
    }

    @Test
    fun config_copy_works() {
        val original = KSafeConfig(keySize = 256, androidAuthValiditySeconds = 30)
        val copied = original.copy(androidAuthValiditySeconds = 60)

        assertEquals(30, original.androidAuthValiditySeconds)
        assertEquals(60, copied.androidAuthValiditySeconds)
        assertEquals(original.keySize, copied.keySize)
    }
}
