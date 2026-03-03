package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KSafeProtectionTest {

    @Test
    fun enumValuesExist() {
        val values = KSafeProtection.entries
        assertEquals(2, values.size)
        assertEquals(KSafeProtection.DEFAULT, values[0])
        assertEquals(KSafeProtection.HARDWARE_ISOLATED, values[1])
    }

    @Test
    fun ordinalOrdering() {
        assertTrue(KSafeProtection.DEFAULT.ordinal < KSafeProtection.HARDWARE_ISOLATED.ordinal)
    }

    @Test
    fun defaultAndHardwareAreDistinct() {
        assertTrue(KSafeProtection.DEFAULT != KSafeProtection.HARDWARE_ISOLATED)
    }
}
