package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Locks in: the 2.2.0 WebAuthn gate on JS/Wasm — first use registers (and counts as a
 * verification), later calls verify against the stored credential id, denials and
 * ceremony errors fail closed, genuine unavailability passes through permissive / refuses
 * strict, the opt-out restores the legacy always-`true` no-op, and the authorization
 * cache keeps the same strength-keyed semantics as every other platform. The real
 * WebAuthn ceremony is replaced by the test seam, so no browser dialogs appear.
 */
class WebBiometricsTest {

    private fun reset() {
        webAuthnCallOverrideForTest = null
        KSafeBiometricsWeb.promptsEnabled = true
        KSafeBiometricsWeb.resetRegistration()
        KSafeBiometrics.clearBiometricAuth()
    }

    @BeforeTest fun setUp() = reset()
    @AfterTest fun tearDown() = reset()

    @Test
    fun optOut_passesThroughWithoutAnyCeremony() = runTest {
        KSafeBiometricsWeb.promptsEnabled = false
        webAuthnCallOverrideForTest = { _, _ -> fail("opt-out must never reach the ceremony") }

        assertTrue(KSafeBiometrics.verifyBiometric("Auth"))
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", allowDeviceCredentialFallback = false))
    }

    @Test
    fun unavailable_permissivePassesThrough_strictRefuses() = runTest {
        webAuthnCallOverrideForTest = { op, _ ->
            assertEquals("available", op, "unavailable path must stop at the availability check")
            "no:no-platform-authenticator"
        }

        assertTrue(
            KSafeBiometrics.verifyBiometric("Auth", allowDeviceCredentialFallback = true),
            "no platform authenticator + permissive → legacy pass-through",
        )
        assertFalse(
            KSafeBiometrics.verifyBiometric("Auth", allowDeviceCredentialFallback = false),
            "no platform authenticator + strict → refuse",
        )
    }

    @Test
    fun firstUse_registersAndCountsAsVerification_thenVerifiesAgainstStoredId() = runTest {
        val ops = mutableListOf<String>()
        webAuthnCallOverrideForTest = { op, arg ->
            ops += op
            when (op) {
                "available" -> "yes"
                "register" -> "registered:cred-abc123"
                "verify" -> { assertEquals("cred-abc123", arg, "verify must use the stored credential id"); "verified" }
                else -> fail("unexpected op $op")
            }
        }

        assertTrue(KSafeBiometrics.verifyBiometric("Auth"), "registration ceremony verifies the user")
        assertEquals("cred-abc123", webBioLocalGet(WEBAUTHN_CREDENTIAL_ID_KEY), "credential id must be persisted")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth"), "second call verifies against the stored id")
        assertEquals(listOf("available", "register", "available", "verify"), ops)
    }

    @Test
    fun denial_failsClosed_andDoesNotSeedTheCache() = runTest {
        webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, "cred-x")
        var prompts = 0
        val answers = ArrayDeque(listOf("denied:NotAllowedError", "verified"))
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) { "available" -> "yes"; "verify" -> { prompts++; answers.removeFirst() }; else -> fail(op) }
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertFalse(KSafeBiometrics.verifyBiometric("Auth", duration), "a cancelled/denied ceremony must return false")
        // The denial must not have seeded the window — the next call prompts again.
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(2, prompts)
    }

    @Test
    fun ceremonyError_failsClosed_evenPermissive() = runTest {
        webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, "cred-x")
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) { "available" -> "yes"; "verify" -> "error:AbortError"; else -> fail(op) }
        }
        assertFalse(
            KSafeBiometrics.verifyBiometric("Auth", allowDeviceCredentialFallback = true),
            "an unexpected ceremony error on a reachable authenticator must fail closed",
        )
    }

    @Test
    fun success_seedsTheCache_noSecondCeremonyWithinWindow() = runTest {
        webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, "cred-x")
        var prompts = 0
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) { "available" -> "yes"; "verify" -> { prompts++; "verified" }; else -> fail(op) }
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(1, prompts, "a cached authorization must not re-prompt inside its window")
    }

    @Test
    fun permissiveCachedSuccess_neverSatisfiesAStrictCall() = runTest {
        webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, "cred-x")
        var prompts = 0
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) { "available" -> "yes"; "verify" -> { prompts++; "verified" }; else -> fail(op) }
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = true))
        assertEquals(1, prompts)
        // Strength keys the cache injectively — the strict call must re-prompt.
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = false))
        assertEquals(2, prompts, "a strict call must re-prompt despite a cached permissive success")
    }

    @Test
    fun clearBiometricAuth_revokesTheCachedWindow() = runTest {
        webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, "cred-x")
        var prompts = 0
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) { "available" -> "yes"; "verify" -> { prompts++; "verified" }; else -> fail(op) }
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        KSafeBiometrics.clearBiometricAuth(scope = "vault")
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(2, prompts, "clearBiometricAuth must force the next call back to a ceremony")
    }

    @Test
    fun resetRegistration_forcesAFreshEnrollment() = runTest {
        val ops = mutableListOf<String>()
        webAuthnCallOverrideForTest = { op, _ ->
            ops += op
            when (op) { "available" -> "yes"; "register" -> "registered:cred-new"; "verify" -> "verified"; else -> fail(op) }
        }

        assertTrue(KSafeBiometrics.verifyBiometric("Auth")) // registers cred-new
        KSafeBiometricsWeb.resetRegistration()
        assertNull(webBioLocalGet(WEBAUTHN_CREDENTIAL_ID_KEY))
        assertTrue(KSafeBiometrics.verifyBiometric("Auth")) // must register again
        assertEquals(listOf("available", "register", "available", "register"), ops)
    }

    @Test
    fun verifyBiometricDirect_deliversTheCallbackResult() = runTest {
        webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, "cred-x")
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) { "available" -> "yes"; "verify" -> "denied:NotAllowedError"; else -> fail(op) }
        }

        val result = CompletableDeferred<Boolean>()
        KSafeBiometrics.verifyBiometricDirect("Auth") { ok -> result.complete(ok) }
        assertFalse(result.await(), "the Direct variant must deliver the ceremony outcome")
    }
}
