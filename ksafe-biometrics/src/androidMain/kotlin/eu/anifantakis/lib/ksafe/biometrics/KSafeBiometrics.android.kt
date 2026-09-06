package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.launch

internal actual suspend fun platformVerifyBiometric(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    title: String?,
    cancelLabel: String?,
): Boolean {
    val attempt = beginBiometricAttempt(authorizationDuration, allowDeviceCredentialFallback)
        ?: return true

    return try {
        // Both hooks run under the gate: skipIfAuthorized re-checks the cache once it is held, and
        // onAuthorized seeds before the gate releases, so that re-check can see it. Only
        // onAuthorized seeds — seeding on a skip would keep extending the authorization window.
        BiometricHelper.authenticate(
            reason, allowDeviceCredentialFallback, title, cancelLabel,
            skipIfAuthorized = { attempt.isFresh() },
            onAuthorized = { attempt.seedIfActive() },
        )
        true
    } catch (e: BiometricAuthException) {
        println("KSafeBiometrics: Biometric authentication failed - ${e.message}")
        false
    } catch (e: BiometricActivityNotFoundException) {
        println("KSafeBiometrics: Biometric Activity not found - ${e.message}")
        false
    } catch (e: CancellationException) {
        // Must precede the generic catch: a cancelled scope is not a denial.
        throw e
    } catch (e: Exception) {
        println("KSafeBiometrics: Unexpected biometric error - ${e.message}")
        false
    }
}

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    title: String?,
    cancelLabel: String?,
    onResult: (Boolean) -> Unit,
) {
    CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
        val ok = platformVerifyBiometric(
            reason, authorizationDuration, allowDeviceCredentialFallback, title, cancelLabel,
        )
        Handler(Looper.getMainLooper()).post { onResult(ok) }
    }
}

private fun androidBiometricsAvailability(allowDeviceCredentialFallback: Boolean): Boolean {
    val context = BiometricHelper.applicationContext ?: return false
    val osEnrolled = androidx.biometric.BiometricManager.from(context)
        .canAuthenticate(allowedAuthenticators(allowDeviceCredentialFallback)) ==
        androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
    // canAuthenticate reports OS enrollment only; authenticate() also needs a FragmentActivity.
    return osEnrolled && BiometricHelper.hasUsableFragmentActivity()
}

internal actual suspend fun platformBiometricsAvailable(allowDeviceCredentialFallback: Boolean): Boolean =
    androidBiometricsAvailability(allowDeviceCredentialFallback)

internal actual fun platformBiometricsAvailableDirect(
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
) {
    val result = runCatching { androidBiometricsAvailability(allowDeviceCredentialFallback) }.getOrDefault(false)
    Handler(Looper.getMainLooper()).post { onResult(result) }
}
