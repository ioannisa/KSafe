package eu.anifantakis.lib.ksafe.biometrics

import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse

/**
 * Drives the real `LAContext.evaluatePolicy` headlessly: with the biometrics-only policy on a Mac
 * without Touch ID (every CI runner) LA answers with an error and shows nothing, so the block
 * plumbing and the blank-reason guard run for real. A Mac with Touch ID would prompt, so there the
 * tests report a skip; kotlin.test has no assumption mechanism on native.
 */
class MacosHeadlessLocalAuthenticationTest {

    private var strictAvailable = true

    @BeforeTest
    fun probe() {
        KSafeBiometrics.clearBiometricAuth()
        strictAvailable = withTestMain { KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false) }
    }

    private fun skipIfTouchIdIsEnrolled(): Boolean {
        if (strictAvailable) println("SKIPPED: Touch ID is enrolled on this Mac; a strict evaluate would show a real prompt")
        return strictAvailable
    }

    @Test
    fun strictEvaluate_withoutTouchId_returnsFalsePromptly_andShowsNothing() {
        if (skipIfTouchIdIsEnrolled()) return
        withTestMain {
            assertFalse(
                platformVerifyBiometric("KSafe headless probe", null, allowDeviceCredentialFallback = false, title = null, cancelLabel = null),
                "LA must reply with an error for the biometrics-only policy on a Mac without Touch ID",
            )
            assertFalse(
                KSafeBiometrics.verifyBiometric("KSafe headless probe", allowDeviceCredentialFallback = false),
                "strict verify on a Mac without Touch ID must refuse, not pass through",
            )
            assertFalse(
                platformVerifyBiometric("KSafe headless probe", null, allowDeviceCredentialFallback = false, title = null, cancelLabel = "Not now"),
                "a custom cancel title takes the same headless path",
            )
        }
    }

    /** An empty `localizedReason` raises `NSInvalidArgumentException` through interop and kills the process. */
    @Test
    fun blankReason_atTheNativeBoundary_neverReachesEvaluatePolicy() {
        if (skipIfTouchIdIsEnrolled()) return
        withTestMain {
            assertFalse(platformVerifyBiometric("", null, allowDeviceCredentialFallback = false, title = null, cancelLabel = null))
            assertFalse(platformVerifyBiometric("   ", null, allowDeviceCredentialFallback = false, title = null, cancelLabel = null))
        }
    }
}
