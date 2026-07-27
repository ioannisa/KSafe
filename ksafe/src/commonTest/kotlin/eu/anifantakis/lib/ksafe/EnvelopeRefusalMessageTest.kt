package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in that a future-envelope refusal cannot be mistaken for a missing key.
 *
 * The refusal exists to PRESERVE an entry a newer KSafe wrote. The engine-to-core protocol is
 * matched on message substrings, so if this message ever carried one of those phrases the entry
 * would be classified as definitively absent and the orphan sweep would delete live ciphertext —
 * the exact opposite of what the refusal is for.
 *
 * Key names are the caller's, and an app that derives them from its own data (a per-user key, say)
 * does not control what ends up inside them, so an interpolated key is untrusted text in a
 * security decision.
 */
class EnvelopeRefusalMessageTest {

    private val classifierPhrases = listOf(
        KSafeEngineMessage.NO_KEY,
        KSafeEngineMessage.KEY_NOT_FOUND,
        KSafeEngineMessage.WEB_KEY_MISSING,
        KSafeEngineMessage.VAULT_UNAVAILABLE,
        KSafeEngineMessage.DEVICE_LOCKED,
    )

    private fun refusalMessageFor(userKey: String): String =
        assertFailsWith<IllegalStateException> {
            KeySafeMetadataManager.checkKnownEnvelopeVersion(
                version = KeySafeMetadataManager.ENVELOPE_VERSION_MAX_KNOWN + 1,
                userKey = userKey,
            )
        }.message.orEmpty()

    @Test
    fun aKeyNamedAfterAClassifierPhrase_cannotSmuggleItIntoTheRefusal() {
        for (phrase in classifierPhrases) {
            val message = refusalMessageFor("session_$phrase")
            assertFalse(
                message.contains(phrase),
                "the refusal must not carry \"$phrase\" — the orphan sweep would read it as a " +
                    "missing key and reap an entry this refusal exists to preserve. Got: $message",
            )
        }
    }

    @Test
    fun theRefusalStillSaysWhatHappenedAndWhatToDo() {
        val message = refusalMessageFor("token")
        assertTrue(message.isNotBlank(), "a refusal with no explanation helps nobody")
        assertTrue(
            message.contains("preserved"),
            "the message must still promise the entry is kept, or a reader will assume data loss",
        )
    }
}
