package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: the 2.2.0 JVM desktop-prompt dispatch — a prompt denial propagates as `false`
 * (the pre-2.2.0 always-`true` no longer masks it), success seeds the authorization cache
 * with strength-keyed slots, and the WinRT pinterface-GUID computation the Windows Hello
 * bridge depends on reproduces published reference GUIDs. The OS prompt itself is
 * replaced by the test seam, so no real dialogs appear.
 */
class DesktopBiometricsTest {

    @BeforeTest
    fun reset() {
        KSafeBiometrics.clearBiometricAuth()
    }

    @AfterTest
    fun tearDown() {
        desktopPromptOverrideForTest = null
        KSafeBiometrics.clearBiometricAuth()
    }

    @Test
    fun promptDenial_propagatesAsFalse() = runBlocking {
        desktopPromptOverrideForTest = { _, _ -> false }
        assertFalse(
            KSafeBiometrics.verifyBiometric("Authenticate"),
            "a denied/cancelled desktop prompt must return false — the legacy always-true would mask it",
        )
    }

    @Test
    fun promptSuccess_returnsTrue_andSeedsTheCache() = runBlocking {
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; true }

        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")
        assertTrue(KSafeBiometrics.verifyBiometric("Authenticate", duration))
        assertEquals(1, prompts)

        // Within the window: served from the cache, no second prompt.
        assertTrue(KSafeBiometrics.verifyBiometric("Authenticate", duration))
        assertEquals(1, prompts, "a cached authorization must not re-prompt inside its window")
    }

    @Test
    fun permissiveSuccess_neverSatisfiesABiometricsOnlyCall() = runBlocking {
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; true }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = true))
        assertEquals(1, prompts)

        // Strength keys the cache injectively: the permissive success must not grant
        // a strict (biometrics-only) call a prompt-free pass.
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = false))
        assertEquals(2, prompts, "a strict call must re-prompt despite a cached permissive success")
    }

    @Test
    fun promptFailure_doesNotSeedTheCache() = runBlocking {
        val answers = ArrayDeque(listOf(false, true))
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; answers.removeFirst() }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertFalse(KSafeBiometrics.verifyBiometric("Auth", duration))
        // The failure must not have seeded the window — the next call prompts again.
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(2, prompts)
    }

    @Test
    fun clearBiometricAuth_revokesTheCachedWindow() = runBlocking {
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; true }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        KSafeBiometrics.clearBiometricAuth(scope = "vault")
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(2, prompts, "clearBiometricAuth must force the next call back to a prompt")
    }

    @Test
    fun optOutProperty_restoresLegacyPassThrough() = runBlocking {
        // No seam here: the property short-circuits before any OS bridge is touched.
        val prior = System.getProperty("ksafe.biometrics.jvm.prompts")
        System.setProperty("ksafe.biometrics.jvm.prompts", "off")
        try {
            assertTrue(
                KSafeBiometrics.verifyBiometric("Authenticate"),
                "the opt-out property must restore the pre-2.2.0 always-true no-op",
            )
        } finally {
            prior?.let { System.setProperty("ksafe.biometrics.jvm.prompts", it) }
                ?: System.clearProperty("ksafe.biometrics.jvm.prompts")
        }
    }

    // ---- WinRT pinterface GUID computation (the Windows Hello bridge depends on it) ----

    @Test
    fun pinterfaceGuid_reproducesPublishedReferenceGuids() {
        // IIterable<String> — published as __FIIterable_1_HSTRING in windows.foundation.collections.h
        assertEquals(
            "e2fcc7c1-3bfc-5a0b-b2b0-72e769d1cb7e",
            WinRtGuid.pinterfaceGuid("pinterface({faa585ea-6214-4217-afda-7f46de5869b3};string)"),
        )
        // IVector<String> — published as __FIVector_1_HSTRING
        assertEquals(
            "98b9acc1-4b56-532e-ac73-03d5291cca90",
            WinRtGuid.pinterfaceGuid("pinterface({913337e9-11a1-4345-a3a2-4e7f956e222d};string)"),
        )
    }

    @Test
    fun asyncOperationGuid_isStableAndWellFormed() {
        val guid = WinRtGuid.ASYNC_OP_USER_CONSENT
        assertTrue(
            Regex("^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").matches(guid),
            "pinterface GUID must be a v5 UUID with RFC 4122 variant; was $guid",
        )
    }

    // ---- Live probe (opt-in): pops a REAL system prompt; excluded from normal runs ----

    @Test
    fun livePrompt_realSystemDialog_optIn() = runBlocking {
        if (System.getProperty("ksafe.biometrics.live") != "1") return@runBlocking
        val ok = KSafeBiometrics.verifyBiometric(
            reason = "KSafe biometrics live verification",
            allowDeviceCredentialFallback = true,
        )
        assertTrue(ok, "live probe: authentication was denied or the prompt failed")
    }
}
