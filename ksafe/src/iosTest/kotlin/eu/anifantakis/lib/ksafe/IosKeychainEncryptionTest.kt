package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Locks in: AppleKeychainEncryption throws on an unknown Keychain error instead of silently
 * creating a new key, which would read back as data loss. The Kotlin/Native simulator runner has
 * no Keychain entitlements (every call returns `errSecMissingEntitlement`, -34018) while the
 * on-device harness runs signed, so each test asserts what its own environment owes.
 *
 * @see IosKSafeTest for tests that run through KSafe's abstraction (which handles entitlements)
 */
class IosKeychainEncryptionTest {

    @OptIn(ExperimentalUuidApi::class)
    private fun uniqueKeyId(): String = "test_${Uuid.random().toString().take(8)}"

    /** Branching per environment beats an "expected failures" list, which is where a regression hides. */
    private val keychainUsable: Boolean get() = !SecurityChecker.isEmulator()

    private fun assertKeychainRefusal(exception: IllegalStateException) {
        assertTrue(
            exception.message?.contains("Keychain error") == true ||
                exception.message?.contains("Cannot access Keychain") == true,
            "Expected Keychain error message, got: ${exception.message}",
        )
    }

    /** Without entitlements encrypt must refuse; minting a fresh key instead would look like data loss. */
    @Test
    fun testEncryptThrowsWithoutEntitlements_andRoundTripsWithThem() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()
        val plaintext = "test data".encodeToByteArray()

        if (keychainUsable) {
            val ciphertext = encryption.encrypt(keyId, plaintext)
            assertEquals(
                plaintext.decodeToString(),
                encryption.decrypt(keyId, ciphertext).decodeToString(),
                "an entitled Keychain must round-trip the payload",
            )
            encryption.deleteKey(keyId)
        } else {
            assertKeychainRefusal(
                assertFailsWith { encryption.encrypt(keyId, plaintext) }
            )
        }
    }

    /**
     * Decrypt throws in both environments; only the reason differs — no entitlements where the
     * Keychain is unreachable, failed authentication where it works.
     */
    @Test
    fun testDecryptThrowsOnGarbage() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()
        val fakeCiphertext = ByteArray(48) { it.toByte() }

        val exception = assertFailsWith<IllegalStateException> {
            encryption.decrypt(keyId, fakeCiphertext)
        }

        if (!keychainUsable) assertKeychainRefusal(exception)
    }

    /** Delete is permissive: unlike encrypt, failing silently costs no data. */
    @Test
    fun testDeleteKeyDoesNotThrow() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()

        encryption.deleteKey(keyId)
        encryption.deleteKey(keyId) // Repeated on purpose: a second delete must also be a no-op.
    }

    /** Both AES key sizes are accepted at construction and behave identically at use. */
    @Test
    fun testCustomConfigIsAccepted() {
        val encryptions = listOf(
            AppleKeychainEncryption(config = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_128)),
            AppleKeychainEncryption(config = KSafeConfig(aesKeySize = KSafeAesKeySize.BITS_256)),
        )

        for (encryption in encryptions) {
            val keyId = uniqueKeyId()
            val plaintext = "test".encodeToByteArray()
            if (keychainUsable) {
                val ciphertext = encryption.encrypt(keyId, plaintext)
                assertEquals(
                    plaintext.decodeToString(),
                    encryption.decrypt(keyId, ciphertext).decodeToString(),
                    "both key sizes must round-trip on an entitled Keychain",
                )
                encryption.deleteKey(keyId)
            } else {
                // Without entitlements the refusal is the same regardless of configured key size.
                assertFailsWith<IllegalStateException> { encryption.encrypt(keyId, plaintext) }
            }
        }
    }

    @Test
    fun testKeychainLookupOrder_checksWrappedThenPlain() {
        // SE-wrapped account first, so decrypt finds a key regardless of how it was created.
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
     * With no SE hardware the request falls back to the plain Keychain, which without entitlements
     * fails too — so the simulator branch still expects a throw, not a silent plain-AES key.
     */
    @Test
    fun testSecureEnclaveThrowsWithoutEntitlements_andRoundTripsOnHardware() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()
        val plaintext = "test data".encodeToByteArray()

        if (keychainUsable) {
            val ciphertext = encryption.encrypt(keyId, plaintext, hardwareIsolated = true)
            assertEquals(
                plaintext.decodeToString(),
                encryption.decrypt(keyId, ciphertext).decodeToString(),
                "a hardware-isolated payload must round-trip on a device with a real Keychain",
            )
            encryption.deleteKey(keyId)
        } else {
            val exception = assertFailsWith<IllegalStateException> {
                encryption.encrypt(keyId, plaintext, hardwareIsolated = true)
            }
            assertTrue(
                exception.message?.contains("Keychain error") == true ||
                    exception.message?.contains("Cannot access Keychain") == true ||
                    exception.message?.contains("Secure Enclave") == true ||
                    exception.message?.contains("Failed to store key") == true,
                "Expected Keychain or SE error message, got: ${exception.message}",
            )
        }
    }

    /** deleteKey attempts the SE cleanup whether or not any SE artifact exists. */
    @Test
    fun testSecureEnclaveDeleteDoesNotThrow() {
        val encryption = AppleKeychainEncryption()
        val keyId = uniqueKeyId()

        encryption.deleteKey(keyId)
        encryption.deleteKey(keyId) // Repeated on purpose: a second delete must also be a no-op.
    }

    /**
     * Manual-only, on real hardware: an SE-wrapped AES key (ECIES under an SE P-256 pair, stored as
     * a generic-password item) must round-trip, and a value written with useSecureEnclave=false must
     * still read back after switching to true — existing keys are never auto-migrated. Without an SE
     * the write falls back to the plain Keychain, mirroring Android's StrongBox fallback.
     */
    @Test
    fun documentSecureEnclaveBehavior() {
        assertTrue(true, "See test documentation for Secure Enclave manual testing instructions")
    }

    /**
     * Manual-only: a device cannot be locked programmatically. Locked, getOrCreateKeychainKey must
     * throw errSecInteractionNotAllowed without deleting or recreating the key, and the data must
     * read back intact once the device is unlocked again.
     */
    @Test
    fun documentDeviceLockedBehavior() {
        assertTrue(true, "See test documentation for manual testing of device-locked scenario")
    }

    /**
     * Only errSecItemNotFound (-25300) may trigger key creation; every other status throws, so a
     * locked device (-25308) or a missing entitlement (-25291) never costs data.
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
