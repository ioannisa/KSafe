package eu.anifantakis.lib.ksafe.biometrics

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Locks in: the authenticator set KSafe asks for is one androidx actually accepts on THIS
 * API level. androidx rejects `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` on API 28-29
 * (`AuthenticatorUtils.isSupportedCombination`), where `PromptInfo.build()` throws and
 * `canAuthenticate` answers UNSUPPORTED — so the permissive prompt could never be shown.
 *
 * Only builds `PromptInfo` and queries `BiometricManager`; no prompt is displayed and no
 * enrolled biometric is needed, so this runs unattended on an emulator.
 *
 * The two API-range tests are mutually exclusive by construction, so exactly one runs per
 * device and the other is reported skipped.
 */
@RunWith(AndroidJUnit4::class)
class AndroidDeviceCredentialAuthenticatorsTest {

    private companion object {
        const val TAG = "KSafeAuthCombinationTest"

        /** androidx's own wording for a rejected combination — distinguishes it from the other IAEs build() throws. */
        const val UNSUPPORTED_MESSAGE = "Authenticator combination is unsupported"
    }

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    /**
     * Mirrors the production prompt: a title (required) and no negative-button text, which
     * androidx forbids whenever DEVICE_CREDENTIAL is allowed.
     */
    private fun buildDeviceCredentialPrompt(authenticators: Int): BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("KSafe authenticator-combination probe")
            .setSubtitle("built, never shown")
            .setConfirmationRequired(true)
            .setAllowedAuthenticators(authenticators)
            .build()

    private val isApi28To29: Boolean
        get() = Build.VERSION.SDK_INT == Build.VERSION_CODES.P ||
            Build.VERSION.SDK_INT == Build.VERSION_CODES.Q

    /** Runs on EVERY device: whatever branch was taken, androidx must accept the result here. */
    @Test
    fun chosenAuthenticators_areAcceptedByAndroidx_onThisDevice() {
        val authenticators = deviceCredentialAuthenticators()
        Log.i(
            TAG,
            "model=${Build.MODEL} api=${Build.VERSION.SDK_INT} isApi28To29=$isApi28To29 " +
                "authenticators=0x${authenticators.toString(16)}",
        )

        // The call that threw on API 28-29 before the fix.
        val promptInfo = buildDeviceCredentialPrompt(authenticators)
        assertEquals(authenticators, promptInfo.allowedAuthenticators)

        val status = BiometricManager.from(context).canAuthenticate(authenticators)
        assertNotEquals(
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
            status,
            "androidx must not report the chosen combination unsupported on API ${Build.VERSION.SDK_INT}",
        )

        // The availability probe must ask about the same set the prompt is built from,
        // or it answers for a prompt that is never shown.
        assertEquals(authenticators, allowedAuthenticators(allowDeviceCredentialFallback = true))
        assertEquals(BIOMETRIC_STRONG, allowedAuthenticators(allowDeviceCredentialFallback = false))
    }

    /**
     * API 28-29 only. Proves the Class 2 branch is load-bearing here: the Class 3 combination
     * the other branch would use is genuinely rejected by androidx on this device.
     */
    @Test
    fun onApi28To29_classThreeIsRejected_soKSafePicksClassTwo() {
        assumeTrue("not API 28-29; the other-API twin covers this class", isApi28To29)

        assertEquals(
            BIOMETRIC_WEAK or DEVICE_CREDENTIAL,
            deviceCredentialAuthenticators(),
            "API ${Build.VERSION.SDK_INT} must use the Class 2 combination",
        )

        val failure = assertFails { buildDeviceCredentialPrompt(BIOMETRIC_STRONG or DEVICE_CREDENTIAL) }
        assertTrue(
            failure.message?.contains(UNSUPPORTED_MESSAGE) == true,
            "PromptInfo.build() must reject the Class 3 combination for the combination reason, was: ${failure.message}",
        )
        assertEquals(
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
            BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL),
            "canAuthenticate must report the Class 3 combination unsupported on API ${Build.VERSION.SDK_INT}",
        )
    }

    /** Every API level outside 28-29: the Class 3 combination is supported, so KSafe keeps it. */
    @Test
    fun outsideApi28To29_classThreeIsAccepted_soKSafeKeepsIt() {
        assumeFalse("API 28-29; the API 28-29 twin covers this class", isApi28To29)

        assertEquals(
            BIOMETRIC_STRONG or DEVICE_CREDENTIAL,
            deviceCredentialAuthenticators(),
            "API ${Build.VERSION.SDK_INT} must use the Class 3 combination",
        )

        val promptInfo = buildDeviceCredentialPrompt(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
        assertEquals(BIOMETRIC_STRONG or DEVICE_CREDENTIAL, promptInfo.allowedAuthenticators)
        assertNotEquals(
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED,
            BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL),
            "the Class 3 combination must be supported on API ${Build.VERSION.SDK_INT}",
        )
    }
}
