package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * iOS-specific test for null filename (default DataStore) behavior.
 */
class IosNullFilenameTest {

    /** Verifies KSafe works with null filename (uses default) */
    @Test
    fun testWithNullFilename() = runTest {
        val ksafe = KSafe(null)  // Explicitly passing null
        
        val key = "test_key"
        val value = "test_value"
        
        ksafe.put(key, value, encrypted = false)
        
        val retrieved = ksafe.get(key, "default", encrypted = false)
        assertEquals(value, retrieved)
    }
    
}