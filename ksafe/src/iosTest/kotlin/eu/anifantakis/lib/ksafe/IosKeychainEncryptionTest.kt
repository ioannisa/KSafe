package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * iOS-specific tests for AppleKeychainEncryption error handling.
 *
 * The Kotlin/Native test runner has no Keychain entitlements, so direct
 * AppleKeychainEncryption calls throw `errSecMissingEntitlement` (-25291).
 * These tests verify exactly that: unknown Keychain errors throw instead of
 * silently creating a new key (which would cause data loss). The device-locked
 * scenario and the full encryption round-trip require manual testing on a
 * device / entitled app.
 *
 * @see IosKSafeTest for tests that run through KSafe's abstraction (which handles entitlements)
 */
class IosKeychainEncryptionTest {

    @OptIn(ExperimentalUuidApi::class)
    private fun uniqueKeyId(): String = "test_${Uuid.random().toString().take(8)}"

    /**
     * Without Keychain entitlements, encrypt must throw rather than silently
     * create a new key. Expected error: errSecMissingEntitlement (-25291).
     */
    @Test
    fun testThrowsOnKeychainErrorInTestEnvironment() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()
        val plaintext = "test data".encodeToByteArray()

        val exception = assertFailsWith<IllegalStateException> {
            encryption.encrypt(keyId, plaintext)
        }

        assertTrue(
            exception.message?.contains("Keychain error") == true ||
            exception.message?.contains("Cannot access Keychain") == true,
            "Expected Keychain error message, got: ${exception.message}"
        )
    }

    /** Decrypt also throws on Keychain errors (does not silently fail). */
    @Test
    fun testDecryptThrowsOnKeychainError() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()
        // Fake ciphertext — the call fails before decryption anyway.
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
     * deleteKey must not throw even in the test environment — delete is
     * permissive (no data-loss risk from failing silently).
     */
    @Test
    fun testDeleteKeyDoesNotThrow() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()

        encryption.deleteKey(keyId)
        encryption.deleteKey(keyId) // Multiple deletes should be safe
    }

    /**
     * Custom configurations are accepted at construction time.
     * (Actual encryption with them requires entitlements.)
     */
    @Test
    fun testCustomConfigIsAccepted() {
        val config128 = KSafeConfig(keySize = 128)
        val config256 = KSafeConfig(keySize = 256)

        val encryption128 = AppleKeychainEncryption(config = config128)
        val encryption256 = AppleKeychainEncryption(config = config256)

        // Both still throw on encrypt (no entitlements), regardless of config.
        val keyId = uniqueKeyId()
        assertFailsWith<IllegalStateException> {
            encryption128.encrypt(keyId, "test".encodeToByteArray())
        }
        assertFailsWith<IllegalStateException> {
            encryption256.encrypt(keyId, "test".encodeToByteArray())
        }
    }

    @Test
    fun testKeychainLookupOrder_checksWrappedThenPlain() {
        // keychainLookupOrder always returns SE-wrapped account first so decrypt
        // can transparently find keys regardless of how they were created.
        val order = AppleKeychainEncryption.keychainLookupOrder(keyId = "mykey")
        assertEquals(listOf("se.mykey", "mykey"), order)
    }

    @Test
    fun testTransientUnwrapFailureClassification_deviceLockedAndInteraction() {
        assertTrue(AppleKeychainEncryption.isTransientUnwrapFailure("device is locked"))
        assertTrue(AppleKeychainEncryption.isTransientUnwrapFailure("Interaction not allowed"))
    }

    @Test
    fun testTransientUnwrapFailureClassification_permanentFailure() {
        assertFalse(AppleKeychainEncryption.isTransientUnwrapFailure("wrong key / corruption"))
        assertFalse(AppleKeychainEncryption.isTransientUnwrapFailure(null))
    }

    /**
     * With no entitlements and no SE hardware, the SE path falls back to plain
     * Keychain — which also fails with errSecMissingEntitlement and must throw.
     */
    @Test
    fun testSecureEnclaveThrowsInTestEnvironment() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()
        val plaintext = "test data".encodeToByteArray()

        val exception = assertFailsWith<IllegalStateException> {
            encryption.encrypt(keyId, plaintext, hardwareIsolated = true)
        }

        // After SE fallback, a Keychain error is expected (same as non-SE in test env).
        assertTrue(
            exception.message?.contains("Keychain error") == true ||
            exception.message?.contains("Cannot access Keychain") == true ||
            exception.message?.contains("Secure Enclave") == true ||
            exception.message?.contains("Failed to store key") == true,
            "Expected Keychain or SE error message, got: ${exception.message}"
        )
    }

    /**
     * deleteKey always attempts to clean up SE artifacts regardless of whether
     * they exist, and never throws — delete is permissive.
     */
    @Test
    fun testSecureEnclaveDeleteDoesNotThrow() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()

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
     * 2. Store a value with put("key", "value") (DEFAULT protection is encrypted)
     * 3. Read it back with get("key", "") → should return "value"
     * 4. Create KSafe with useSecureEnclave=false
     * 5. Store a different value with put("key2", "value2") (DEFAULT protection is encrypted)
     * 6. Switch back to useSecureEnclave=true
     * 7. Read key2 → should return "value2" (legacy key is still readable)
     */
    @Test
    fun documentSecureEnclaveBehavior() {
        assertTrue(true, "See test documentation for Secure Enclave manual testing instructions")
    }

    /**
     * Documents the expected behavior for errSecInteractionNotAllowed.
     *
     * This cannot be tested automatically (the device cannot be locked
     * programmatically); it serves as documentation for manual testing.
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
        val expectedCodes = mapOf(
            0 to "errSecSuccess - operation succeeded",
            -25300 to "errSecItemNotFound - key doesn't exist, safe to create",
            -25308 to "errSecInteractionNotAllowed - device locked, throw error",
            -25291 to "errSecMissingEntitlement - no keychain access, throw error"
        )

        assertTrue(expectedCodes.isNotEmpty(), "Error codes documented")
    }
}
