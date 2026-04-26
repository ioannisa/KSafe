package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.CoreFoundation.CFAbsoluteTimeGetCurrent
import platform.Foundation.NSProcessInfo
import kotlin.concurrent.AtomicReference

/**
 * iOS implementation of [KSafeBiometrics] platform helpers.
 *
 * Real `LAContext` (Face ID / Touch ID). Returns `true` on the simulator
 * (no biometric hardware available).
 */

private val biometricAuthSessions = AtomicReference<Map<String, Long>>(emptyMap())

@OptIn(ExperimentalForeignApi::class)
private fun currentTimeMillis(): Long =
    ((CFAbsoluteTimeGetCurrent() + 978307200.0) * 1000).toLong()

@OptIn(ExperimentalForeignApi::class)
private fun isSimulator(): Boolean =
    NSProcessInfo.processInfo.environment["SIMULATOR_UDID"] != null

private fun updateBiometricSession(scope: String, timestamp: Long) {
    while (true) {
        val current = biometricAuthSessions.value
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
        val lastAuth = biometricAuthSessions.value[scope] ?: 0L
        val now = currentTimeMillis()
        if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
            return true
        }
    }

    if (isSimulator()) {
        if (authorizationDuration != null) {
            updateBiometricSession(authorizationDuration.scope ?: "", currentTimeMillis())
        }
        return true
    }

    return suspendCancellableCoroutine { continuation ->
        runLAContextEvaluate(reason) { success ->
            if (success && authorizationDuration != null) {
                updateBiometricSession(authorizationDuration.scope ?: "", currentTimeMillis())
            }
            continuation.resumeWith(Result.success(success))
        }
    }
}

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    onResult: (Boolean) -> Unit,
) {
    CoroutineScope(Dispatchers.Main).launch {
        if (authorizationDuration != null && authorizationDuration.duration > 0) {
            val scope = authorizationDuration.scope ?: ""
            val lastAuth = biometricAuthSessions.value[scope] ?: 0L
            val now = currentTimeMillis()
            if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
                onResult(true)
                return@launch
            }
        }
        if (isSimulator()) {
            if (authorizationDuration != null) {
                updateBiometricSession(authorizationDuration.scope ?: "", currentTimeMillis())
            }
            onResult(true)
            return@launch
        }
        runLAContextEvaluate(reason) { success ->
            if (success && authorizationDuration != null) {
                updateBiometricSession(authorizationDuration.scope ?: "", currentTimeMillis())
            }
            onResult(success)
        }
    }
}

internal actual fun platformClearBiometricAuth(scope: String?) {
    if (scope == null) {
        biometricAuthSessions.value = emptyMap()
        return
    }
    while (true) {
        val current = biometricAuthSessions.value
        val updated = current - scope
        if (biometricAuthSessions.compareAndSet(current, updated)) break
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun runLAContextEvaluate(reason: String, onResult: (Boolean) -> Unit) {
    val context = platform.LocalAuthentication.LAContext()
    val policy = platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics
    context.evaluatePolicy(policy, localizedReason = reason) { success, _ ->
        CoroutineScope(Dispatchers.Main).launch { onResult(success) }
    }
}
