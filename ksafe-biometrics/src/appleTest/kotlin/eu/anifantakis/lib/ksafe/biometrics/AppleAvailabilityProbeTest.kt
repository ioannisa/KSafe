package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CompletableDeferred
import platform.LocalAuthentication.LAContext
import platform.LocalAuthentication.LAPolicyDeviceOwnerAuthentication
import platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in the prompt-free availability probe on both Apple test hosts: on the Simulator it is
 * `false` for either strength (verify is a pass-through there), on macOS it is exactly what
 * `LAContext.canEvaluatePolicy` says for the policy the prompt would use. Nothing here shows UI.
 */
class AppleAvailabilityProbeTest {

    @OptIn(ExperimentalForeignApi::class)
    private fun laContextSays(allowDeviceCredentialFallback: Boolean): Boolean =
        LAContext().canEvaluatePolicy(
            if (allowDeviceCredentialFallback) LAPolicyDeviceOwnerAuthentication
            else LAPolicyDeviceOwnerAuthenticationWithBiometrics,
            error = null,
        )

    @Test
    fun availabilityProbe_answersWithoutUi_andMatchesTheHost() = withTestMain {
        val strict = KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false)
        val permissive = KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = true)

        if (runningOnSimulator()) {
            assertFalse(strict, "Simulator: verify passes through, so no real prompt is available")
            assertFalse(permissive)
        } else {
            assertEquals(laContextSays(false), strict, "strict must ask LAContext about the biometrics-only policy")
            assertEquals(laContextSays(true), permissive, "permissive must ask about device-owner auth")
            if (strict) assertTrue(permissive, "biometrics is a subset of device-owner auth")
        }
    }

    @Test
    fun availabilityDirect_deliversTheSameAnswerOnMain() = withTestMain {
        val strict = CompletableDeferred<Boolean>()
        val permissive = CompletableDeferred<Boolean>()
        KSafeBiometrics.biometricsAvailableDirect(allowDeviceCredentialFallback = false) { strict.complete(it) }
        KSafeBiometrics.biometricsAvailableDirect(allowDeviceCredentialFallback = true) { permissive.complete(it) }

        assertEquals(KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false), strict.await())
        assertEquals(KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = true), permissive.await())
    }
}
