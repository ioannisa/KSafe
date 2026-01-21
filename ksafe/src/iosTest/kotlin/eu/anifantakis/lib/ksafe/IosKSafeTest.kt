package eu.anifantakis.lib.ksafe

import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * iOS-specific test implementation for KSafe.
 * Generates unique file names using UUID to avoid DataStore conflicts.
 */
class IosKSafeTest : KSafeTest() {
    
    @OptIn(ExperimentalUuidApi::class)
    override fun createKSafe(fileName: String?): KSafe {
        // If no filename is provided, generate a unique one for each test
        // to avoid DataStore conflicts on iOS
        val actualFileName = fileName ?: Uuid.random().toString()
            .lowercase()
            .filter { it in 'a'..'z' }
            .take(20) // Limit length to keep it reasonable
            
        // Use FakeEncryption to bypass Keychain entitlement issues in test environment
        return KSafe(
            fileName = actualFileName,
            testEngine = FakeEncryption()
        )
    }
}