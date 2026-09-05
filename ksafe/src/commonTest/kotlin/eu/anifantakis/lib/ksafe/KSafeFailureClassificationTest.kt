package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage
import eu.anifantakis.lib.ksafe.internal.coreparts.isOrphanProbeFailure
import eu.anifantakis.lib.ksafe.internal.coreparts.isRotationRetryable
import eu.anifantakis.lib.ksafe.internal.coreparts.isTransientDecryptFailure
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in the engine-to-core failure protocol: which messages mean "this key is gone for good"
 * (the orphan sweep deletes the ciphertext) and which mean "try again later".
 *
 * Both verdicts are read off a message, and engine messages interpolate the caller's key or alias.
 * So the definitive phrases are recognised only in their canonical `"KSafe: <phrase>"` opening —
 * an unanchored search anywhere in the message lets a key named after a phrase decide the verdict
 * for the entry it names.
 */
class KSafeFailureClassificationTest {

    private fun failure(message: String): Throwable = IllegalStateException(message)

    @Test
    fun vaultOutageWhoseAliasReadsLikeAMissIsPreserved() {
        // JVM: the alias is "[fileName:]userKey", so the user key lands inside the outage message.
        assertFalse(
            isOrphanProbeFailure(
                failure(
                    "KSafe: key ${KSafeEngineMessage.VAULT_UNAVAILABLE} — Windows DPAPI could not " +
                        "unprotect the stored key for alias \"api key not found counter\" " +
                        "(the user's master key changed).",
                ),
            ),
            "a vault outage must never be reaped as an orphan just because the alias reads like a miss",
        )
        // Apple: the account embeds the user key for HARDWARE_ISOLATED entries.
        assertFalse(
            isOrphanProbeFailure(
                failure(
                    "KSafe: ${KSafeEngineMessage.KEYCHAIN} error -25291 for account " +
                        "se.eu.anifantakis.ksafe.diag.key not found.retryCount",
                ),
            ),
            "a Keychain outage must never be reaped as an orphan because the account reads like a miss",
        )
    }

    @Test
    fun aVaultOutageIsNeitherTransientNorReapable_butRotationStillRetriesIt() {
        val outage = failure(
            "KSafe: key ${KSafeEngineMessage.VAULT_UNAVAILABLE} (degraded); " +
                "cannot resolve key for identifier: token",
        )
        assertFalse(isTransientDecryptFailure(outage), "reads take the default on an outage, they don't retry")
        assertFalse(isOrphanProbeFailure(outage), "an outage is recoverable — the ciphertext stays")
        assertTrue(isRotationRetryable(outage), "a rotation pauses on an outage and retries next pass")
    }

    @Test
    fun aDeadWebKeyIsDefinitive_evenWhenTheRecordNameReadsLikeAKeystore() {
        // Web record name = "<ns>:ksafe_<fileName>_ksafe_key_<alias>", so a store named
        // "keystore" puts the transient classifier's own brand inside a definitive message.
        val dead = failure("KSafe: ${KSafeEngineMessage.WEB_KEY_MISSING}: ksafe_keystore_ksafe_key_keystore:token")
        assertFalse(
            isTransientDecryptFailure(dead),
            "a definitively dead web key must not read as a retryable hiccup — getFlow would loop forever",
        )
        assertTrue(isOrphanProbeFailure(dead), "a definitively dead web key leaves ciphertext to reclaim")
    }

    @Test
    fun aDeadWebKeyStaysDefinitiveOnceTheWasmRuntimeHasRewrappedIt() {
        // Kotlin/Wasm hands the core its own wrapper, so the brand is no longer at position 0.
        val wrapped = failure(
            "Non-Kotlin exception Error: ${KSafeEngineMessage.WEB_KEY_MISSING_PREFIX}" +
                "ksafe_vault_ksafe_key_tok of type 'class Error'",
        )
        assertTrue(isOrphanProbeFailure(wrapped), "the wasm wrapper must not hide a dead key from the sweep")
        assertFalse(isTransientDecryptFailure(wrapped))
    }

    @Test
    fun canonicalMissIsDefinitive_evenWhenTheIdentifierReadsLikeAKeystore() {
        val miss = failure(KSafeEngineMessage.noKeyFound("keystore_x"))
        assertTrue(isOrphanProbeFailure(miss), "the canonical miss is what the sweep reclaims on")
        assertFalse(isTransientDecryptFailure(miss), "an absent key is never worth retrying")
    }

    @Test
    fun aLockedDeviceStaysTransientAndKeepsItsCiphertext() {
        val locked = failure(
            "KSafe: Cannot access ${KSafeEngineMessage.KEYSTORE} key - ${KSafeEngineMessage.DEVICE_LOCKED}.",
        )
        assertTrue(isTransientDecryptFailure(locked), "a locked device is the canonical retryable fault")
        assertFalse(isOrphanProbeFailure(locked), "a locked device must never cost the user their data")
    }

    @Test
    fun anUnrecognisedFailurePreservesTheEntryAndIsNotRetried() {
        val unknown = failure("KSafe: Failed to unwrap AES key with Secure Enclave: bad blob [osstatus=-26275]")
        assertFalse(isOrphanProbeFailure(unknown), "an error the protocol doesn't name preserves the entry")
        assertFalse(isTransientDecryptFailure(unknown), "an error the protocol doesn't name is not retried")

        val noMessage = IllegalStateException()
        assertFalse(isOrphanProbeFailure(noMessage))
        assertFalse(isTransientDecryptFailure(noMessage))
    }
}
