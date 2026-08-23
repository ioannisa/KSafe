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
        // Both hooks run under the gate: skipIfAuthorized re-checks the cache once it is held, so a
        // caller queued behind one that just authenticated skips a redundant second prompt, and
        // onAuthorized seeds before the gate is released so that re-check can actually see it.
        // Seeding only from onAuthorized also keeps the rule that a skip must not extend the window.
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
        // Rethrow, don't map to false: a cancelled scope must not read as "denied". Must precede
        // the generic catch, since CancellationException is an Exception.
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

/** Synchronous platform check backing both `biometricsAvailable` variants. */
private fun androidBiometricsAvailability(allowDeviceCredentialFallback: Boolean): Boolean {
    // Null context means the init ContentProvider was stripped/not initialized — can't ask the OS.
    val context = BiometricHelper.applicationContext ?: return false
    val osEnrolled = androidx.biometric.BiometricManager.from(context)
        .canAuthenticate(allowedAuthenticators(allowDeviceCredentialFallback)) ==
        androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
    // canAuthenticate answers OS enrollment only; authenticate() also requires a FragmentActivity
    // host, which a plain ComponentActivity (the default Compose base class) is not. Gate on both
    // so a false positive doesn't make callers skip their own fallback.
    return osEnrolled && BiometricHelper.hasUsableFragmentActivity()
}

internal actual suspend fun platformBiometricsAvailable(allowDeviceCredentialFallback: Boolean): Boolean =
    androidBiometricsAvailability(allowDeviceCredentialFallback)

internal actual fun platformBiometricsAvailableDirect(
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
) {
    val result = runCatching { androidBiometricsAvailability(allowDeviceCredentialFallback) }.getOrDefault(false)
    // Main-thread delivery, like the other Android callbacks.
    Handler(Looper.getMainLooper()).post { onResult(result) }
}
