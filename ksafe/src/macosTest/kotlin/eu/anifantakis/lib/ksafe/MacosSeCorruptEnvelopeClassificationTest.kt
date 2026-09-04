package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: the Secure Enclave key pair and its wrapped AES key are destroyed only on positive
 * proof that the envelope is corrupt. Any other unwrap failure — an unrecognised OSStatus from a
 * securityd/SEP hiccup, or a CFError outside the OSStatus domain that carries no code at all —
 * must leave both halves intact, or every HARDWARE_ISOLATED value for that alias is unreadable.
 */
class MacosSeCorruptEnvelopeClassificationTest {

    private fun seFailure(localized: String, osstatus: Long): String =
        "KSafe: Failed to unwrap AES key with Secure Enclave: $localized [osstatus=$osstatus]"

    @Test
    fun decodeError_isProvablyCorrupt() {
        // errSecDecode (-26275): the wrapped blob really is undecodable.
        assertTrue(AppleKeychainEncryption.isProvablyCorruptEnvelope(seFailure("bad data", -26275)))
    }

    @Test
    fun paramError_isProvablyCorrupt() {
        // errSecParam (-50): the blob is not a valid ECIES envelope for this key.
        assertTrue(AppleKeychainEncryption.isProvablyCorruptEnvelope(seFailure("bad param", -50)))
    }

    @Test
    fun unrecognisedOsStatus_isNotProvablyCorrupt() {
        listOf(-2070L, -67671L, -36L, -108L).forEach { code ->
            assertFalse(
                AppleKeychainEncryption.isProvablyCorruptEnvelope(seFailure("…", code)),
                "osstatus=$code is not proof of corruption and must not destroy the SE key",
            )
        }
    }

    @Test
    fun transientOsStatus_isNotProvablyCorrupt() {
        listOf(-25308L, -25291L, -25293L, -128L).forEach { code ->
            assertFalse(
                AppleKeychainEncryption.isProvablyCorruptEnvelope(seFailure("…", code)),
                "transient osstatus=$code must not destroy the SE key",
            )
        }
    }

    @Test
    fun untaggedMessage_isNotProvablyCorrupt() {
        // A CFError outside NSOSStatusErrorDomain carries no [osstatus=] tag at all.
        assertFalse(
            AppleKeychainEncryption.isProvablyCorruptEnvelope(
                "KSafe: Failed to unwrap AES key with Secure Enclave: The operation couldn't be completed.",
            ),
        )
        assertFalse(AppleKeychainEncryption.isProvablyCorruptEnvelope("bad data decode error"))
        assertFalse(AppleKeychainEncryption.isProvablyCorruptEnvelope(null))
    }

    /**
     * The outer SE catch in `getOrCreateKeychainKey` recognises a propagated unwrap failure by
     * substring, so the message `unwrapAesKey` actually throws must keep carrying it — otherwise
     * the failure is read as "SE unavailable" and the alias silently downgrades to a plain key.
     */
    @Test
    fun unwrapFailureMessage_carriesTheMarkerTheOuterCatchMatches() {
        val msg = AppleKeychainEncryption.seFailureMessage("unwrap", "boom [osstatus=-2070]")
        assertTrue(
            msg.contains("Failed to unwrap AES key with Secure Enclave"),
            "outer catch keys on this substring; was: $msg",
        )
    }
}
