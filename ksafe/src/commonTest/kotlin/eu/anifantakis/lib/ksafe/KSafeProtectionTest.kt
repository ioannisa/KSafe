package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KSafeProtectionTest {

    @Test
    fun enumValuesExist() {
        val values = KSafeProtection.entries
        assertEquals(3, values.size)
        assertEquals(KSafeProtection.NONE, values[0])
        assertEquals(KSafeProtection.DEFAULT, values[1])
        assertEquals(KSafeProtection.HARDWARE_ISOLATED, values[2])
    }

    @Test
    fun ordinalOrdering() {
        assertTrue(KSafeProtection.NONE.ordinal < KSafeProtection.DEFAULT.ordinal)
        assertTrue(KSafeProtection.DEFAULT.ordinal < KSafeProtection.HARDWARE_ISOLATED.ordinal)
    }

    @Test
    fun noneIsNotEncrypted() {
        assertEquals(false, KSafeProtection.NONE != KSafeProtection.NONE)
        assertEquals(true, KSafeProtection.DEFAULT != KSafeProtection.NONE)
        assertEquals(true, KSafeProtection.HARDWARE_ISOLATED != KSafeProtection.NONE)
    }
}
