package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicReference

/**
 * Android implementation of [KSafeBiometrics] platform helpers.
 *
 * Real `BiometricPrompt` (BIOMETRIC_STRONG + DEVICE_CREDENTIAL). Activity
 * tracking is bootstrapped automatically by [KSafeBiometricsInitProvider]
 * during process startup — no consumer init required.
 */

/**
 * Per-scope last-success timestamp. Lets verify-paths skip the platform
 * prompt when a caller-supplied [BiometricAuthorizationDuration] is still
 * valid for the given scope.
 */
private val biometricAuthSessions = AtomicReference<Map<String, Long>>(emptyMap())

private fun updateBiometricSession(scope: String, timestamp: Long) {
    while (true) {
        val current = biometricAuthSessions.get()
        val updated = current + (scope to timestamp)
        if (biometricAuthSessions.compareAndSet(current, updated)) break
    }
}

internal actual suspend fun platformVerifyBiometric(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
): Boolean {
    if (authorizationDuration != null && authorizationDuration.duration > 0) {
        val scope = authorizationDuration.scope ?: ""
        val lastAuth = biometricAuthSessions.get()[scope] ?: 0L
        val now = System.currentTimeMillis()
        if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
            return true
        }
    }

    return try {
        BiometricHelper.authenticate(reason)
        if (authorizationDuration != null) {
            updateBiometricSession(authorizationDuration.scope ?: "", System.currentTimeMillis())
        }
        true
    } catch (e: BiometricAuthException) {
        println("KSafeBiometrics: Biometric authentication failed - ${e.message}")
        false
    } catch (e: BiometricActivityNotFoundException) {
        println("KSafeBiometrics: Biometric Activity not found - ${e.message}")
        false
    } catch (e: Exception) {
        println("KSafeBiometrics: Unexpected biometric error - ${e.message}")
        false
    }
}

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    onResult: (Boolean) -> Unit,
) {
    CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
        onResult(platformVerifyBiometric(reason, authorizationDuration))
    }
}

internal actual fun platformClearBiometricAuth(scope: String?) {
    if (scope == null) {
        biometricAuthSessions.set(emptyMap())
        return
    }
    while (true) {
        val current = biometricAuthSessions.get()
        val updated = current - scope
        if (biometricAuthSessions.compareAndSet(current, updated)) break
    }
}
