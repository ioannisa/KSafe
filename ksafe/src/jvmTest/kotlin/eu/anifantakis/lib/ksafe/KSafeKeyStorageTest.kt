package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
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
    fun getKeyInfo_returnsNullForNonExistentKey() {
        val ksafe = KSafe(fileName = "keyinfoquerytest")
        val result = ksafe.getKeyInfo("nonexistent_key")
        assertNull(result)
    }

    @Test
    fun getKeyInfo_returnsNoneProtectionAndSoftwareForUnencryptedKey() {
        val ksafe = KSafe(fileName = "keyinfounenctest")
        ksafe.putDirect("plain_key", "hello", mode = KSafeWriteMode.Plain)
        val result = ksafe.getKeyInfo("plain_key")
        assertEquals(KSafeKeyInfo(null, KSafeKeyStorage.SOFTWARE), result)
    }

    @Test
    fun getKeyInfo_returnsDefaultProtectionAndSoftwareForEncryptedKey() {
        val ksafe = KSafe(fileName = "keyinfoenctest")
        ksafe.putDirect("secret_key", "secret_value")
        val result = ksafe.getKeyInfo("secret_key")
        assertEquals(KSafeKeyInfo(KSafeProtection.DEFAULT, KSafeKeyStorage.SOFTWARE), result)
    }

    @Test
    fun getKeyInfo_protectionMatchesStoredMetadata() {
        val ksafe = KSafe(fileName = "keyinfometatest")

        ksafe.putDirect("none_key", "value", mode = KSafeWriteMode.Plain)
        ksafe.putDirect("default_key", "value", mode = KSafeWriteMode.Encrypted())

        val noneInfo = ksafe.getKeyInfo("none_key")
        assertEquals(null, noneInfo?.protection)
        assertEquals(KSafeKeyStorage.SOFTWARE, noneInfo?.storage)

        val defaultInfo = ksafe.getKeyInfo("default_key")
        assertEquals(KSafeProtection.DEFAULT, defaultInfo?.protection)
        assertEquals(KSafeKeyStorage.SOFTWARE, defaultInfo?.storage)
    }

}
