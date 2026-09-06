package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CompletableDeferred
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in the documented Simulator contract: `verifyBiometric` returns `true` for either strength
 * without a prompt, the Direct variant delivers the same, and `biometricsAvailable()` says `false`.
 * The iOS test binary only ever runs on the Simulator, so the precondition fails loudly elsewhere.
 */
class IosSimulatorPassThroughTest {

    @BeforeTest
    fun onTheSimulator() {
        assertTrue(runningOnSimulator(), "these tests describe the Simulator; run them there")
        KSafeBiometrics.clearBiometricAuth()
    }

    @Test
    fun verify_isAPassThrough_forEitherStrength() = withTestMain {
        assertTrue(KSafeBiometrics.verifyBiometric("Unlock"))
        assertTrue(KSafeBiometrics.verifyBiometric("Unlock", allowDeviceCredentialFallback = false))
        assertTrue(
            KSafeBiometrics.verifyBiometric(
                "Unlock",
                authorizationDuration = BiometricAuthorizationDuration(60_000L, scope = "sim"),
            ),
        )
        assertFalse(KSafeBiometrics.biometricsAvailable(), "a pass-through is not a real prompt")
        assertFalse(KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false))
    }

    @Test
    fun verifyDirect_deliversTrue() = withTestMain {
        val result = CompletableDeferred<Boolean>()
        KSafeBiometrics.verifyBiometricDirect("Unlock", allowDeviceCredentialFallback = false) { result.complete(it) }
        assertTrue(result.await())
    }

    @Test
    fun blankReason_atTheActual_neverReachesEvaluatePolicy() = withTestMain {
        // The Simulator branch returns before LAContext is even constructed.
        assertTrue(platformVerifyBiometric("", null, allowDeviceCredentialFallback = false, title = null, cancelLabel = null))
    }
}
