package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSUserDomainMask
import okio.Path.Companion.toPath
import okio.FileSystem
import kotlinx.cinterop.ExperimentalForeignApi

/**
 * iOS-specific debug test for verifying encryption behavior.
 * Includes detailed logging and DataStore file inspection.
 */
class IosDebugTest {
    
    /** Debug test verifying encrypted/unencrypted storage with detailed logging */
    @OptIn(ExperimentalForeignApi::class)
    @Test
    fun testSimpleEncryptionDebug() = runTest {
        println("\n=== iOS Debug Test Starting ===")
        
        // Create a KSafe instance with a specific filename
        val testFileName = "debugtest"
        // Use FakeEncryption to bypass Keychain entitlement issues in test environment
        val ksafe = KSafe(fileName = testFileName, testEngine = FakeEncryption())
        println("Created KSafe with filename: $testFileName")
        
        // Store an unencrypted value
        val unencryptedKey = "test_unencrypted"
        val unencryptedValue = "plain_text_value"
        ksafe.put(unencryptedKey, unencryptedValue, encrypted = false)
        println("Stored unencrypted: key='$unencryptedKey', value='$unencryptedValue'")
        
        // Store an encrypted value
        val encryptedKey = "test_encrypted"
        val encryptedValue = "secret_value"
        ksafe.put(encryptedKey, encryptedValue, encrypted = true)
        println("Stored encrypted: key='$encryptedKey', value='$encryptedValue'")
        
        // Try to retrieve the values
        val retrievedUnencrypted = ksafe.get(unencryptedKey, "default_unencrypted", encrypted = false)
        println("Retrieved unencrypted: '$retrievedUnencrypted' (expected: '$unencryptedValue')")
        assertEquals(unencryptedValue, retrievedUnencrypted)
        
        // Try retrieving as unencrypted to see what's stored
        val rawEncrypted = ksafe.get("debugtest_test_encrypted", "not_found", encrypted = false)
        println("Raw encrypted data key check: '$rawEncrypted'")
        
        val retrievedEncrypted = ksafe.get(encryptedKey, "default_encrypted", encrypted = true)
        println("Retrieved encrypted: '$retrievedEncrypted' (expected: '$encryptedValue')")
        
        // Now let's examine the DataStore file directly
        val docDir = NSFileManager.defaultManager.URLForDirectory(
            directory = NSDocumentDirectory,
            inDomain = NSUserDomainMask,
            appropriateForURL = null,
            create = true,
            error = null
        )
        
        val dataStorePath = requireNotNull(docDir?.path) { "Failed to get Documents directory" }
            .plus("/eu_anifantakis_ksafe_datastore_$testFileName.preferences_pb")
            .toPath()
        
        println("\nDataStore file path: $dataStorePath")
        
        // Read and display the DataStore contents
        try {
            val fileSystem = FileSystem.SYSTEM
            if (fileSystem.exists(dataStorePath)) {
                val contents = fileSystem.read(dataStorePath) {
                    readUtf8()
                }
                println("\nDataStore raw contents (length: ${contents.length}):")
                println("---START---")
                // Print each line with its bytes for debugging
                contents.lines().forEachIndexed { index, line ->
                    if (line.isNotEmpty()) {
                        println("Line $index: $line")
                        val bytes = line.encodeToByteArray()
                        println("  Bytes: ${bytes.joinToString(" ") { byte -> byte.toInt().and(0xFF).toString(16).padStart(2, '0') }}")
                    }
                }
                println("---END---")
                
                // Check for specific keys in the content
                println("\nSearching for keys in DataStore:")
                println("  Contains 'test_unencrypted': ${contents.contains("test_unencrypted")}")
                println("  Contains 'test_encrypted': ${contents.contains("test_encrypted")}")
                println("  Contains 'debugtest_test_encrypted': ${contents.contains("debugtest_test_encrypted")}")
                println("  Contains 'encrypted_test_encrypted': ${contents.contains("encrypted_test_encrypted")}")
                
            } else {
                println("DataStore file does not exist!")
            }
        } catch (e: Exception) {
            println("Error reading DataStore file: ${e.message}")
            e.printStackTrace()
        }
        
        // Final assertion
        assertEquals(encryptedValue, retrievedEncrypted, "Encrypted value retrieval failed")
        
        println("\n=== iOS Debug Test Complete ===\n")
    }
}