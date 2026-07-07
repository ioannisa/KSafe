package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: Secure-Enclave unwrap failures are classified transient-vs-permanent by the
 * locale-independent `[osstatus=<code>]` tag, not English substrings in the CFError's
 * localized description. Misclassifying a transient locked-device failure as permanent
 * would delete the non-exportable SE key and destroy every HARDWARE_ISOLATED ciphertext.
 */
class MacosSecUnwrapClassificationTest {

    private fun seFailure(localized: String, osstatus: Long): String =
        "KSafe: Failed to unwrap AES key with Secure Enclave: $localized [osstatus=$osstatus]"

    @Test
    fun lockedDevice_nonEnglishText_isTransient_byCode() {
        // errSecInteractionNotAllowed (-25308), non-English text with no English trigger words.
        val msg = seFailure("L'opération n'a pas pu être terminée.", -25308)
        assertTrue(AppleKeychainEncryption.isTransientUnwrapFailure(msg))
    }

    @Test
    fun keychainNotAvailable_isTransient_byCode() {
        // errSecNotAvailable (-25291): securityd not ready (e.g. pre-first-unlock).
        assertTrue(AppleKeychainEncryption.isTransientUnwrapFailure(seFailure("…", -25291)))
    }

    @Test
    fun authFailed_isTransient_byCode() {
        // errSecAuthFailed (-25293).
        assertTrue(AppleKeychainEncryption.isTransientUnwrapFailure(seFailure("…", -25293)))
    }

    @Test
    fun userCancelled_isTransient_byCode() {
        // errSecUserCanceled (-128).
        assertTrue(AppleKeychainEncryption.isTransientUnwrapFailure(seFailure("…", -128)))
    }

    @Test
    fun decodeError_isNotTransient_soRegenerationProceeds() {
        // errSecDecode (-26275): the wrapped blob really is undecodable.
        assertFalse(AppleKeychainEncryption.isTransientUnwrapFailure(seFailure("bad data", -26275)))
    }

    @Test
    fun explicitWording_isTransient_viaFallback() {
        assertTrue(
            AppleKeychainEncryption.isTransientUnwrapFailure(
                "KSafe: Cannot access Keychain - device is locked. Key exists but is inaccessible.",
            ),
        )
    }

    @Test
    fun unrelatedFailure_isNotTransient() {
        assertFalse(AppleKeychainEncryption.isTransientUnwrapFailure("KSafe: some unrelated failure"))
        assertFalse(AppleKeychainEncryption.isTransientUnwrapFailure(null))
    }

    // The core's isTransientDecryptFailure (used on the DECRYPT path) matches the
    // "Keychain" brand, not the osstatus tag, so the SE failure message must carry that
    // brand when — and only when — the code is transient.

    @Test
    fun seFailureMessage_transientCode_isBrandedForCoreClassifier() {
        val msg = AppleKeychainEncryption.seFailureMessage(
            "unwrap",
            "L'opération n'a pas pu être terminée. [osstatus=-25308]",
        )
        assertTrue(msg.contains("Keychain"), "transient SE failure must carry the core-recognized brand; was: $msg")
    }

    @Test
    fun seFailureMessage_permanentCode_isNotBranded() {
        // errSecDecode (-26275): genuine corruption must stay core-permanent.
        val msg = AppleKeychainEncryption.seFailureMessage("unwrap", "bad blob [osstatus=-26275]")
        assertFalse(msg.contains("Keychain"), "permanent SE failure must NOT classify transient; was: $msg")
        assertFalse(msg.contains("device is locked", ignoreCase = true))
    }
}
