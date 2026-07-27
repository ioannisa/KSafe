package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/**
 * Locks in: KSafeConfig defaults, key-size validation, and data-class behavior.
 */
class KSafeConfigTest {

    @Test
    fun defaultConfig_hasCorrectDefaults() {
        val config = KSafeConfig()

        assertEquals(256, config.keySize, "Default keySize should be 256")
        assertFalse(config.requireUnlockedDevice, "Default requireUnlockedDevice should be false")
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
    fun config_equality_works() {
        val config1 = KSafeConfig(keySize = 256)
        val config2 = KSafeConfig(keySize = 256)
        val config3 = KSafeConfig(keySize = 128)

        assertEquals(config1, config2, "Same configs should be equal")
        assertFalse(config1 == config3, "Different configs should not be equal")
    }

    @Test
    fun config_copy_works() {
        val original = KSafeConfig(keySize = 256)
        val copied = original.copy(keySize = 128)

        assertEquals(256, original.keySize)
        assertEquals(128, copied.keySize)
        assertEquals(original.requireUnlockedDevice, copied.requireUnlockedDevice)
    }
}
