package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the transient-vs-permanent classification of Secure-Enclave unwrap
 * failures.
 *
 * Classification must key on the locale-independent `[osstatus=<code>]` tag
 * that `cfErrorDescription` embeds for OSStatus-domain errors. Matching
 * English substrings ("device is locked" / "interaction") against the
 * CFError's *localized* description fails on a non-English device, where a
 * transient `errSecInteractionNotAllowed` (and friends) renders to text
 * containing neither word — a recoverable, locked-device / SE-busy failure
 * would then be treated as permanent corruption, deleting the non-exportable
 * SE key and permanently destroying every HARDWARE_ISOLATED ciphertext under
 * it.
 *
 * These cases run natively on macOS (`macosArm64Test`) and need no device —
 * the classifier is a pure function over the error string, which is exactly
 * the destructive decision point.
 */
class MacosSecUnwrapClassificationTest {

    private fun seFailure(localized: String, osstatus: Long): String =
        "KSafe: Failed to unwrap AES key with Secure Enclave: $localized [osstatus=$osstatus]"

    // ---- transient codes classify transient regardless of localized text ----

    @Test
    fun lockedDevice_nonEnglishText_isTransient_byCode() {
        // errSecInteractionNotAllowed (-25308), French-ish localized text with
        // none of the English trigger words — the case the code tag exists for.
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

    // ---- the DECRYPT path must also classify transient — the engine-side
    // classifier above is only consulted on key CREATION; the core's
    // isTransientDecryptFailure matches "device is locked"/"Keystore"/"Keychain"
    // and never parses the osstatus tag. So the SE failure message itself must
    // carry the "Keychain" brand when (and only when) the code is transient.

    @Test
    fun seFailureMessage_transientCode_isBrandedForCoreClassifier() {
        val msg = AppleKeychainEncryption.seFailureMessage(
            "unwrap",
            "L'opération n'a pas pu être terminée. [osstatus=-25308]",
        )
        // "Keychain" is the substring KSafeCore.isTransientDecryptFailure keys on
        // (pinned by JvmObservableFlowResilienceTest for the flow-skip behavior).
        assertTrue(msg.contains("Keychain"), "transient SE failure must carry the core-recognized brand; was: $msg")
    }

    @Test
    fun seFailureMessage_permanentCode_isNotBranded() {
        // errSecDecode (-26275): genuine corruption must stay core-permanent so
        // reads fall through to default and the self-heal/orphan logic applies.
        val msg = AppleKeychainEncryption.seFailureMessage("unwrap", "bad blob [osstatus=-26275]")
        assertFalse(msg.contains("Keychain"), "permanent SE failure must NOT classify transient; was: $msg")
        assertFalse(msg.contains("device is locked", ignoreCase = true))
    }
}
