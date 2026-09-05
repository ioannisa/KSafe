package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
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
        webAuthnAbortOverrideForTest = null
        webBioLocalRemoveOverrideForTest = null
        KSafeBiometricsWeb.promptsEnabled = true
        KSafeBiometricsWeb.resetRegistration()
        KSafeBiometrics.clearBiometricAuth()
        KSafeBiometrics.defaultTitle = null
    }

    @BeforeTest fun setUp() = reset()
    @AfterTest fun tearDown() = reset()

    @Test
    fun registerCeremony_carriesTheTitleThatNamesThePasskey() = runTest {
        // The passkey's visible name in the user's password manager comes from the title;
        // without it the credential is listed under the library's own fallback name.
        var registerArg: String? = "<never called>"
        webAuthnCallOverrideForTest = { op, arg ->
            when (op) {
                "available" -> "yes"
                "register" -> { registerArg = arg; "registered:cred-1" }
                else -> fail("unexpected op $op")
            }
        }

        KSafeBiometrics.defaultTitle = "Commercials Manager"
        assertTrue(KSafeBiometrics.verifyBiometric("Unlock"))
        assertEquals("Commercials Manager", registerArg, "the title must reach the register ceremony")
    }

    @Test
    fun registerCeremony_withoutATitle_passesNullSoTheDispatcherFallsBack() = runTest {
        var registerArg: String? = "<never called>"
        webAuthnCallOverrideForTest = { op, arg ->
            when (op) {
                "available" -> "yes"
                "register" -> { registerArg = arg; "registered:cred-1" }
                else -> fail("unexpected op $op")
            }
        }

        assertTrue(KSafeBiometrics.verifyBiometric("Unlock"))
        assertNull(registerArg, "no title set -> null, and the JS dispatcher supplies the fallback name")
    }

    @Test
    fun registration_isIntrospectable_andTheRenameMigrationRunsExactlyOnce() = runTest {
        var registrations = 0
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) {
                "available" -> "yes"
                "register" -> { registrations++; "registered:cred-1" }
                "verify" -> "verified"
                "signalUnknown" -> "signal:ok" // fired by the reset below; asserted separately
                else -> fail("unexpected op $op")
            }
        }

        assertFalse(KSafeBiometricsWeb.isRegistered, "nothing enrolled yet")
        assertNull(KSafeBiometricsWeb.registeredTitle)

        KSafeBiometrics.defaultTitle = "Old Name"
        assertTrue(KSafeBiometrics.verifyBiometric("Unlock"))
        assertTrue(KSafeBiometricsWeb.isRegistered, "the ceremony stored a credential id")
        assertEquals("Old Name", KSafeBiometricsWeb.registeredTitle)
        assertEquals(1, registrations)

        // The app renames itself: the mismatch is visible, so the app resets deliberately.
        KSafeBiometrics.defaultTitle = "New Name"
        assertEquals("Old Name", KSafeBiometricsWeb.registeredTitle, "the stored name is unchanged")
        if (KSafeBiometricsWeb.isRegistered &&
            KSafeBiometricsWeb.registeredTitle != KSafeBiometrics.defaultTitle
        ) {
            KSafeBiometricsWeb.resetRegistration()
        }
        assertFalse(KSafeBiometricsWeb.isRegistered, "reset forgets the enrollment")

        // Next verification re-enrolls under the new name...
        assertTrue(KSafeBiometrics.verifyBiometric("Unlock"))
        assertEquals("New Name", KSafeBiometricsWeb.registeredTitle)
        assertEquals(2, registrations)

        // ...and the migration condition is now false, so it never fires again.
        assertFalse(
            KSafeBiometricsWeb.isRegistered &&
                KSafeBiometricsWeb.registeredTitle != KSafeBiometrics.defaultTitle,
            "the rename migration must be self-limiting",
        )
    }

    @Test
    fun resetRegistration_signalsTheAbandonedCredentialToThePasskeyProvider() = runTest {
        // A reset forgets the credential locally, but the passkey itself survives in the user's
        // password manager and would sit beside the next enrollment. The signal asks the provider
        // to drop it; it is advisory and best-effort, so the reset must complete either way.
        val signalled = CompletableDeferred<String?>()
        webAuthnCallOverrideForTest = { op, arg ->
            when (op) {
                "available" -> "yes"
                "register" -> "registered:cred-xyz"
                "signalUnknown" -> { signalled.complete(arg); "signal:ok" }
                else -> fail("unexpected op $op")
            }
        }

        assertTrue(KSafeBiometrics.verifyBiometric("Unlock"))
        assertTrue(KSafeBiometricsWeb.isRegistered)

        KSafeBiometricsWeb.resetRegistration()

        assertEquals(
            "cred-xyz", signalled.await(),
            "the abandoned credential id must reach the provider, not the new one",
        )
        assertFalse(KSafeBiometricsWeb.isRegistered, "the local record is cleared regardless")
    }

    @Test
    fun resetRegistration_survivesAStorageBlockedRemoval() = runTest {
        // "Block all cookies" / a sandboxed iframe: the localStorage getter throws SecurityError.
        // resetRegistration is a non-suspending public API wired to a button, so the throw must
        // not escape it, nor cost the title slot and the abandoned-credential signal after it.
        val signalled = CompletableDeferred<String?>()
        webAuthnCallOverrideForTest = { op, arg ->
            when (op) {
                "available" -> "yes"
                "register" -> "registered:cred-blocked"
                "signalUnknown" -> { signalled.complete(arg); "signal:ok" }
                else -> fail("unexpected op $op")
            }
        }

        KSafeBiometrics.defaultTitle = "Blocked Origin"
        assertTrue(KSafeBiometrics.verifyBiometric("Unlock"))
        assertEquals("Blocked Origin", KSafeBiometricsWeb.registeredTitle)

        webBioLocalRemoveOverrideForTest = { key ->
            if (key == WEBAUTHN_CREDENTIAL_ID_KEY) throw IllegalStateException("SecurityError")
            webBioLocalRemove(key)
        }
        try {
            KSafeBiometricsWeb.resetRegistration()
        } finally {
            webBioLocalRemoveOverrideForTest = null
            webBioLocalRemove(WEBAUTHN_CREDENTIAL_ID_KEY)
        }

        assertNull(KSafeBiometricsWeb.registeredTitle, "the title slot must still be cleared")
        assertEquals("cred-blocked", signalled.await(), "the abandoned credential must still be signalled")
    }

    @Test
    fun resetRegistration_withNothingEnrolled_signalsNothing() = runTest {
        webAuthnCallOverrideForTest = { op, _ -> fail("nothing enrolled must not signal (op $op)") }
        KSafeBiometricsWeb.resetRegistration()
        assertFalse(KSafeBiometricsWeb.isRegistered)
    }

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
    fun resetRegistration_alsoRevokesCachedAuthorizationWindows() = runTest {
        val ops = mutableListOf<String>()
        webAuthnCallOverrideForTest = { op, _ ->
            ops += op
            when (op) { "available" -> "yes"; "register" -> "registered:cred-new"; "verify" -> "verified"; else -> fail(op) }
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration)) // registers + seeds the window
        KSafeBiometricsWeb.resetRegistration()
        // The cached window was earned under the removed credential — the next call must run a
        // fresh registration ceremony, not answer prompt-free from the cache.
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(listOf("available", "register", "available", "register"), ops)
    }

    @Test
    fun clearDuringAnInFlightCeremony_isNotUndoneByItsSuccess() = runTest {
        webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, "cred-x")
        var prompts = 0
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) {
                "available" -> "yes"
                "verify" -> {
                    prompts++
                    // Logout raced the open ceremony: revocation lands before the user completes it.
                    if (prompts == 1) KSafeBiometrics.clearBiometricAuth()
                    "verified"
                }
                else -> fail(op)
            }
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration), "the in-flight caller still gets its result")
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(2, prompts, "a success landing after clearBiometricAuth must not re-seed the window")
    }

    @Test
    fun scopedClearOfAnUnrelatedScope_doesNotRevokeTheInFlightCeremony() = runTest {
        webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, "cred-x")
        var prompts = 0
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) {
                "available" -> "yes"
                "verify" -> {
                    prompts++
                    if (prompts == 1) KSafeBiometrics.clearBiometricAuth(scope = "other")
                    "verified"
                }
                else -> fail(op)
            }
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(1, prompts, "revoking an unrelated scope must not cost this scope its seeded window")
    }

    @Test
    fun cancellingAnInFlightCeremony_abortsIt_andFreesTheGate() = runTest {
        webBioLocalSet(WEBAUTHN_CREDENTIAL_ID_KEY, "cred-x")
        var aborted = false
        webAuthnAbortOverrideForTest = { aborted = true }
        val ceremonyStarted = CompletableDeferred<Unit>()
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) {
                "available" -> "yes"
                "verify" -> { ceremonyStarted.complete(Unit); awaitCancellation() }
                else -> fail(op)
            }
        }

        val caller = launch { KSafeBiometrics.verifyBiometric("Auth") }
        ceremonyStarted.await()
        caller.cancelAndJoin()
        assertTrue(aborted, "cancelling the awaiting coroutine must abort the in-flight browser ceremony")

        // The gate must be free and the next call must run a fresh ceremony.
        webAuthnCallOverrideForTest = { op, _ ->
            when (op) { "available" -> "yes"; "verify" -> "verified"; else -> fail(op) }
        }
        assertTrue(KSafeBiometrics.verifyBiometric("Auth"), "a cancelled ceremony must not strand the next caller")
    }

    @Test
    fun biometricsAvailable_trueWhenPlatformAuthenticatorExists() = runTest {
        webAuthnCallOverrideForTest = { op, _ ->
            assertEquals("available", op, "availability must not run any prompt ceremony")
            "yes"
        }
        assertTrue(KSafeBiometrics.biometricsAvailable())
        assertTrue(KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false))
    }

    @Test
    fun biometricsAvailable_falseWhenAbsent_andWhenOptedOut() = runTest {
        webAuthnCallOverrideForTest = { _, _ -> "no:no-platform-authenticator" }
        assertFalse(KSafeBiometrics.biometricsAvailable())

        KSafeBiometricsWeb.promptsEnabled = false
        webAuthnCallOverrideForTest = { _, _ -> fail("opt-out must not reach the ceremony") }
        assertFalse(
            KSafeBiometrics.biometricsAvailable(),
            "opted-out verify is a pass-through, so availability must report no real prompt",
        )
    }

    @Test
    fun biometricsAvailableDirect_deliversTheCallbackResult() = runTest {
        webAuthnCallOverrideForTest = { _, _ -> "yes" }
        val result = CompletableDeferred<Boolean>()
        KSafeBiometrics.biometricsAvailableDirect { available -> result.complete(available) }
        assertTrue(result.await())
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
