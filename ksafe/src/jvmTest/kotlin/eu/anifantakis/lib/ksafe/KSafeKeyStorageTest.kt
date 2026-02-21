package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KSafeKeyStorageTest {

    @Test
    fun deviceKeyStorages_returnsOnlySoftware() {
        val ksafe = KSafe(fileName = "keystoragetest")
        assertEquals(setOf(KSafeKeyStorage.SOFTWARE), ksafe.deviceKeyStorages)
    }

    @Test
    fun activeKeyStorage_returnsSoftware() {
        val ksafe = KSafe(fileName = "keystorageactivetest")
        assertEquals(KSafeKeyStorage.SOFTWARE, ksafe.activeKeyStorage)
    }

    @Test
    fun enumOrdinalOrdering() {
        assertTrue(KSafeKeyStorage.SOFTWARE.ordinal < KSafeKeyStorage.HARDWARE_BACKED.ordinal)
        assertTrue(KSafeKeyStorage.HARDWARE_BACKED.ordinal < KSafeKeyStorage.HARDWARE_ISOLATED.ordinal)
    }
}
