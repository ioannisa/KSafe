package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the transient-vs-permanent classification of Secure-Enclave unwrap
 * failures (deep-review #31).
 *
 * The bug: classification matched the English substrings "device is locked" /
 * "interaction" against the CFError's *localized* description. On a non-English
 * device a transient `errSecInteractionNotAllowed` (and friends) renders to text
 * containing neither word, so a recoverable, locked-device / SE-busy failure was
 * treated as permanent corruption — deleting the non-exportable SE key and
 * permanently destroying every HARDWARE_ISOLATED ciphertext under it.
 *
 * The fix classifies on the locale-independent `[osstatus=<code>]` tag that
 * `cfErrorDescription` now embeds for OSStatus-domain errors. These cases run
 * natively on macOS (`macosArm64Test`) and need no device — the classifier is a
 * pure function over the error string, which is exactly the destructive decision
 * point.
 */
class MacosSecUnwrapClassificationTest {

    private fun seFailure(localized: String, osstatus: Long): String =
        "KSafe: Failed to unwrap AES key with Secure Enclave: $localized [osstatus=$osstatus]"

    // ---- #31: transient codes classify transient regardless of localized text ----

    @Test
    fun lockedDevice_nonEnglishText_isTransient_byCode() {
        // errSecInteractionNotAllowed (-25308), French-ish localized text with
        // none of the English trigger words — the exact #31 failure case.
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
        // errSecAuthFailed (-25293): retryable, must not destroy the key.
        assertTrue(AppleKeychainEncryption.isTransientUnwrapFailure(seFailure("…", -25293)))
    }

    @Test
    fun userCancelled_isTransient_byCode() {
        // errSecUserCanceled (-128): user dismissed the auth prompt.
        assertTrue(AppleKeychainEncryption.isTransientUnwrapFailure(seFailure("…", -128)))
    }

    // ---- permanent codes stay permanent so genuine corruption still self-heals ----

    @Test
    fun decodeError_isNotTransient_soRegenerationProceeds() {
        // errSecDecode (-26275): the wrapped blob really is undecodable.
        assertFalse(AppleKeychainEncryption.isTransientUnwrapFailure(seFailure("bad data", -26275)))
    }

    // ---- fallback: hand-written ISE wording (no code tag) still classifies ----

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
}
