package eu.anifantakis.lib.ksafe

import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * iOS-specific test implementation for KSafe.
 * Generates unique file names using UUID to avoid DataStore conflicts.
 */
class IosKSafeTest : KSafeTest() {
    
    @OptIn(ExperimentalUuidApi::class)
    override fun newKSafe(fileName: String?): KSafe {
        val actualFileName = fileName ?: Uuid.random().toString()
            .lowercase()
            .filter { it in 'a'..'z' }
            .take(20)

        // FakeEncryption bypasses Keychain entitlement issues in the test environment.
        return KSafe(
            fileName = actualFileName,
            testEngine = FakeEncryption()
        )
    }
}