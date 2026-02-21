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
    fun enumOrdinalOrdering() {
        assertTrue(KSafeKeyStorage.SOFTWARE.ordinal < KSafeKeyStorage.HARDWARE_BACKED.ordinal)
        assertTrue(KSafeKeyStorage.HARDWARE_BACKED.ordinal < KSafeKeyStorage.HARDWARE_ISOLATED.ordinal)
    }

    @Test
    fun getKeyStorage_returnsNullForNonExistentKey() {
        val ksafe = KSafe(fileName = "keystoragequerytest")
        val result = ksafe.getKeyStorage("nonexistent_key")
        assertEquals(null, result)
    }

    @Test
    fun getKeyStorage_returnsSoftwareForUnencryptedKey() {
        val ksafe = KSafe(fileName = "keystorageunenctest")
        ksafe.putDirect("plain_key", "hello", protection = KSafeProtection.NONE)
        val result = ksafe.getKeyStorage("plain_key")
        assertEquals(KSafeKeyStorage.SOFTWARE, result)
    }

    @Test
    fun getKeyStorage_returnsSoftwareForEncryptedKey() {
        val ksafe = KSafe(fileName = "keystorageenctest")
        ksafe.putDirect("secret_key", "secret_value")
        val result = ksafe.getKeyStorage("secret_key")
        assertEquals(KSafeKeyStorage.SOFTWARE, result)
    }
}
