package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** Locks in: `KSafe(null)` falls back to the default DataStore name and still round-trips on iOS. */
class IosNullFilenameTest {

    @Test
    fun testWithNullFilename() = runTest {
        val ksafe = KSafe(null)
        
        val key = "test_key"
        val value = "test_value"
        
        ksafe.put(key, value, KSafeWriteMode.Plain)

        val retrieved = ksafe.get(key, "default")
        assertEquals(value, retrieved)
    }
    
}