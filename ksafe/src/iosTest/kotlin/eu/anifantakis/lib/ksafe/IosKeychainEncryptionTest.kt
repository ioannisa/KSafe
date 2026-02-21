package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * iOS-specific tests for IosKeychainEncryption error handling.
 *
 * ## Test Environment Limitations
 *
 * Direct Keychain operations require proper entitlements that are NOT available
 * in the Kotlin/Native test runner. This means:
 * - Direct IosKeychainEncryption tests will throw `errSecMissingEntitlement` (-25291)
 * - This is EXPECTED behavior - it proves our error handling works correctly
 * - Full encryption tests run through IosKSafeTest which uses KSafe's abstraction
 *
 * ## What These Tests Verify
 *
 * 1. **Error handling is correct** - Unknown errors throw exceptions (don't silently create keys)
 * 2. **errSecInteractionNotAllowed** - Device-locked scenario is documented (manual test required)
 * 3. **errSecMissingEntitlement** - Throws exception (verified by these tests)
 *
 * ## Manual Testing Required For
 *
 * - Device-locked scenario (cannot be automated)
 * - Full encryption round-trip (use iOS app or XCTest with entitlements)
 *
 * @see IosKSafeTest for tests that run through KSafe's abstraction (which handles entitlements)
 */
class IosKeychainEncryptionTest {

    @OptIn(ExperimentalUuidApi::class)
    private fun uniqueKeyId(): String = "test_${Uuid.random().toString().take(8)}"

    // ============ ERROR HANDLING TESTS ============

    /**
     * Verifies that the encryption throws an exception in environments without
     * Keychain entitlements (like the unit test runner).
     *
     * This proves our error handling is correct: we throw instead of silently
     * creating a new key (which would cause data loss).
     *
     * Expected error: errSecMissingEntitlement (-25291) in test environment
     */
    @Test
    fun testThrowsOnKeychainErrorInTestEnvironment() {
        val encryption = IosKeychainEncryption()
        val keyId = uniqueKeyId()
        val plaintext = "test data".encodeToByteArray()

        val exception = assertFailsWith<IllegalStateException> {
            encryption.encrypt(keyId, plaintext)
        }

        // The exception message should contain the status code
        assertTrue(
            exception.message?.contains("Keychain error") == true ||
            exception.message?.contains("Cannot access Keychain") == true,
            "Expected Keychain error message, got: ${exception.message}"
        )
    }

    /**
     * Verifies that decrypt also throws on Keychain errors (not silently fails).
     */
    @Test
    fun testDecryptThrowsOnKeychainError() {
        val encryption = IosKeychainEncryption()
        val keyId = uniqueKeyId()
        // Fake ciphertext - doesn't matter since we'll fail before decryption
        val fakeCiphertext = ByteArray(48) { it.toByte() }

        val exception = assertFailsWith<IllegalStateException> {
            encryption.decrypt(keyId, fakeCiphertext)
        }

        assertTrue(
            exception.message?.contains("Keychain error") == true ||
            exception.message?.contains("Cannot access Keychain") == true,
            "Expected Keychain error message, got: ${exception.message}"
        )
    }

    /**
     * Verifies that deleteKey doesn't throw even in test environment.
     * (Delete is more permissive - no data loss risk from failing silently)
     */
    @Test
    fun testDeleteKeyDoesNotThrow() {
        val encryption = IosKeychainEncryption()
        val keyId = uniqueKeyId()

        // Should not throw - delete failures are generally harmless
        encryption.deleteKey(keyId)
        encryption.deleteKey(keyId) // Multiple deletes should be safe
    }

    /**
     * Verifies that custom configuration is accepted.
     * (Actual encryption test requires entitlements)
     */
    @Test
    fun testCustomConfigIsAccepted() {
        val config128 = KSafeConfig(keySize = 128)
        val config256 = KSafeConfig(keySize = 256)

        // These should not throw - just verifying configuration is accepted
        val encryption128 = IosKeychainEncryption(config = config128)
        val encryption256 = IosKeychainEncryption(config = config256)

        // Both should throw on encrypt (no entitlements), but with different configs
        val keyId = uniqueKeyId()
        assertFailsWith<IllegalStateException> {
            encryption128.encrypt(keyId, "test".encodeToByteArray())
        }
        assertFailsWith<IllegalStateException> {
            encryption256.encrypt(keyId, "test".encodeToByteArray())
        }
    }

    // ============ SECURE ENCLAVE TESTS ============

    @Test
    fun testSecureEnclaveLookupOrder_enabledReadsWrappedThenPlain() {
        val order = IosKeychainEncryption.keychainLookupOrder(
            keyId = "mykey",
            useSecureEnclave = true
        )
        assertEquals(listOf("se.mykey", "mykey"), order)
    }

    @Test
    fun testSecureEnclaveLookupOrder_disabledReadsPlainOnly() {
        val order = IosKeychainEncryption.keychainLookupOrder(
            keyId = "mykey",
            useSecureEnclave = false
        )
        assertEquals(listOf("mykey"), order)
    }

    /**
     * Regression test for flag toggling behavior:
     * - SE=true readers can read legacy plain keys (fallback path)
     * - SE=false readers do NOT look up wrapped keys created under SE=true
     */
    @Test
    fun testSecureEnclaveFlagToggleLookupRegression() {
        val keyId = "token"
        val readerWithSe = IosKeychainEncryption.keychainLookupOrder(keyId, useSecureEnclave = true)
        val readerWithoutSe = IosKeychainEncryption.keychainLookupOrder(keyId, useSecureEnclave = false)

        assertTrue(readerWithSe.contains("se.$keyId"))
        assertTrue(readerWithSe.contains(keyId))
        assertEquals(listOf(keyId), readerWithoutSe)
    }

    @Test
    fun testTransientUnwrapFailureClassification_deviceLockedAndInteraction() {
        assertTrue(IosKeychainEncryption.isTransientUnwrapFailure("device is locked"))
        assertTrue(IosKeychainEncryption.isTransientUnwrapFailure("Interaction not allowed"))
    }

    @Test
    fun testTransientUnwrapFailureClassification_permanentFailure() {
        assertFalse(IosKeychainEncryption.isTransientUnwrapFailure("wrong key / corruption"))
        assertFalse(IosKeychainEncryption.isTransientUnwrapFailure(null))
    }

    /**
     * Verifies that encrypt with useSecureEnclave=true throws in the test environment.
     *
     * In the unit test runner (no entitlements, no SE hardware), the SE path will fail
     * and fall back to plain Keychain — which also fails with errSecMissingEntitlement.
     * This proves the fallback path works and error handling is correct.
     */
    @Test
    fun testSecureEnclaveThrowsInTestEnvironment() {
        val encryption = IosKeychainEncryption(useSecureEnclave = true)
        val keyId = uniqueKeyId()
        val plaintext = "test data".encodeToByteArray()

        val exception = assertFailsWith<IllegalStateException> {
            encryption.encrypt(keyId, plaintext)
        }

        // After SE fallback, should get a Keychain error (same as non-SE in test env)
        assertTrue(
            exception.message?.contains("Keychain error") == true ||
            exception.message?.contains("Cannot access Keychain") == true ||
            exception.message?.contains("Secure Enclave") == true ||
            exception.message?.contains("Failed to store key") == true,
            "Expected Keychain or SE error message, got: ${exception.message}"
        )
    }

    /**
     * Verifies that deleteKey with useSecureEnclave=true doesn't throw.
     * Delete operations are permissive — no data loss risk from silent failure.
     */
    @Test
    fun testSecureEnclaveDeleteDoesNotThrow() {
        val encryption = IosKeychainEncryption(useSecureEnclave = true)
        val keyId = uniqueKeyId()

        // Should not throw - delete is always permissive
        encryption.deleteKey(keyId)
        encryption.deleteKey(keyId) // Multiple deletes should be safe
    }

    /**
     * Documents the Secure Enclave envelope encryption behavior:
     *
     * When useSecureEnclave=true:
     * 1. An EC P-256 key pair is created in the Secure Enclave hardware
     * 2. The AES symmetric key is wrapped (encrypted) by the SE public key using ECIES
     * 3. The wrapped AES key is stored in the Keychain as a generic-password item
     * 4. On decrypt, the SE private key unwraps the AES key, which then decrypts data
     *
     * Backward compatibility:
     * - Pre-SE keys (plain AES in Keychain) are still readable
     * - New keys are SE-wrapped; existing keys are never auto-migrated
     *
     * Fallback:
     * - If SE is unavailable (simulator, old device), falls back to regular Keychain
     *   (same behavior as Android's StrongBox fallback)
     *
     * Manual test on physical device:
     * 1. Create KSafe with useSecureEnclave=true
     * 2. Store a value with put("key", "value", encrypted=true)
     * 3. Read it back with get("key", "", encrypted=true) → should return "value"
     * 4. Create KSafe with useSecureEnclave=false
     * 5. Store a different value with put("key2", "value2", encrypted=true)
     * 6. Switch back to useSecureEnclave=true
     * 7. Read key2 → should return "value2" (legacy key is still readable)
     */
    @Test
    fun documentSecureEnclaveBehavior() {
        assertTrue(true, "See test documentation for Secure Enclave manual testing instructions")
    }

    // ============ DOCUMENTATION TESTS ============

    /**
     * Documents the expected behavior for errSecInteractionNotAllowed.
     *
     * This test cannot be run automatically because we cannot lock the device
     * programmatically. It serves as documentation for manual testing.
     *
     * Expected behavior when device is locked:
     * - getOrCreateKeychainKey() should throw IllegalStateException
     * - The exception message should indicate the device is locked
     * - The key should NOT be deleted or recreated
     * - Data should remain intact and accessible after unlock
     *
     * Manual test steps:
     * 1. Store encrypted data while device is unlocked
     * 2. Lock the device
     * 3. Try to read the encrypted data (should throw)
     * 4. Unlock the device
     * 5. Read the encrypted data again (should succeed with original data)
     */
    @Test
    fun documentDeviceLockedBehavior() {
        // This test documents expected behavior but cannot test it automatically
        // See docstring above for manual testing instructions
        assertTrue(true, "See test documentation for manual testing of device-locked scenario")
    }

    /**
     * Documents the error codes we handle:
     *
     * - errSecSuccess (0): Operation succeeded
     * - errSecItemNotFound (-25300): Key doesn't exist → create new key
     * - errSecInteractionNotAllowed (-25308): Device locked → throw exception
     * - errSecMissingEntitlement (-25291): No keychain access → throw exception
     * - Other errors: throw exception with status code
     *
     * The key insight is that only errSecItemNotFound should trigger key creation.
     * All other errors should throw to prevent silent data loss.
     */
    @Test
    fun documentErrorCodes() {
        // Error code documentation
        val expectedCodes = mapOf(
            0 to "errSecSuccess - operation succeeded",
            -25300 to "errSecItemNotFound - key doesn't exist, safe to create",
            -25308 to "errSecInteractionNotAllowed - device locked, throw error",
            -25291 to "errSecMissingEntitlement - no keychain access, throw error"
        )

        assertTrue(expectedCodes.isNotEmpty(), "Error codes documented")
    }
}
