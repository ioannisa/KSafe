package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.Foundation.NSProcessInfo
import kotlin.time.TimeSource
import kotlin.concurrent.AtomicReference
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.OsFamily
import kotlin.native.Platform

/**
 * Apple-platform [KSafeBiometrics] helpers.
 *
 * iOS: Face ID / Touch ID via `LAPolicyDeviceOwnerAuthenticationWithBiometrics`; returns `true` on the Simulator.
 * macOS: `LAPolicyDeviceOwnerAuthentication` — Touch ID, password, or Apple Watch unlock.
 */

private val biometricAuthSessions = AtomicReference<Map<String, Long>>(emptyMap())

// Monotonic TTL clock: a backward wall-clock jump (NTP or manual change) must NOT extend a
// cached authorization. TimeSource.Monotonic never goes backward.
private val biometricClockOrigin = TimeSource.Monotonic.markNow()
private fun monotonicNowMs(): Long = biometricClockOrigin.elapsedNow().inWholeMilliseconds

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
    allowDeviceCredentialFallback: Boolean,
): Boolean {
    if (BiometricAuthSession.shouldCache(authorizationDuration)) {
        val scope = BiometricAuthSession.sessionKey(authorizationDuration!!.scope, requireStrict = !allowDeviceCredentialFallback)
        val lastAuth = biometricAuthSessions.value[scope] ?: 0L
        val now = monotonicNowMs()
        if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
            return true
        }
    }

    if (isSimulator()) {
        if (BiometricAuthSession.shouldCache(authorizationDuration)) {
            seedBiometricSessionIfActive {
                updateBiometricSession(BiometricAuthSession.sessionKey(authorizationDuration!!.scope, requireStrict = !allowDeviceCredentialFallback), monotonicNowMs())
            }
        }
        return true
    }

    return suspendCancellableCoroutine { continuation ->
        // Own the LAContext so a cancelled coroutine can invalidate() the pending prompt, and guard
        // resume so a late or repeated callback can't resume an already-resumed continuation.
        val context = platform.LocalAuthentication.LAContext()
        continuation.invokeOnCancellation { runCatching { context.invalidate() } }
        CoroutineScope(Dispatchers.Main).launch {
            runLAContextEvaluate(context, reason, allowDeviceCredentialFallback) { success ->
                // Seed only if the continuation is still active: a success arriving after the caller
                // cancelled must NOT seed the cache, or a later call gets a prompt-free pass off an
                // authorization never received.
                if (success && BiometricAuthSession.shouldCache(authorizationDuration) && continuation.isActive) {
                    updateBiometricSession(BiometricAuthSession.sessionKey(authorizationDuration!!.scope, requireStrict = !allowDeviceCredentialFallback), monotonicNowMs())
                }
                if (continuation.isActive) continuation.resumeWith(Result.success(success))
            }
        }
    }
}

internal actual fun platformVerifyBiometricDirect(
    reason: String,
    authorizationDuration: BiometricAuthorizationDuration?,
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
) {
    CoroutineScope(Dispatchers.Main).launch {
        if (BiometricAuthSession.shouldCache(authorizationDuration)) {
            val scope = BiometricAuthSession.sessionKey(authorizationDuration!!.scope, requireStrict = !allowDeviceCredentialFallback)
            val lastAuth = biometricAuthSessions.value[scope] ?: 0L
            val now = monotonicNowMs()
            if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
                onResult(true)
                return@launch
            }
        }
        if (isSimulator()) {
            if (BiometricAuthSession.shouldCache(authorizationDuration)) {
                updateBiometricSession(BiometricAuthSession.sessionKey(authorizationDuration!!.scope, requireStrict = !allowDeviceCredentialFallback), monotonicNowMs())
            }
            onResult(true)
            return@launch
        }
        runLAContextEvaluate(platform.LocalAuthentication.LAContext(), reason, allowDeviceCredentialFallback) { success ->
            if (success && BiometricAuthSession.shouldCache(authorizationDuration)) {
                updateBiometricSession(BiometricAuthSession.sessionKey(authorizationDuration!!.scope, requireStrict = !allowDeviceCredentialFallback), monotonicNowMs())
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
    // Clear BOTH the permissive and strict slots for this scope (see BiometricAuthSession).
    val permissiveKey = BiometricAuthSession.sessionKey(scope, requireStrict = false)
    val strictKey = BiometricAuthSession.sessionKey(scope, requireStrict = true)
    while (true) {
        val current = biometricAuthSessions.value
        val updated = current - permissiveKey - strictKey
        if (biometricAuthSessions.compareAndSet(current, updated)) break
    }
}

@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
private fun runLAContextEvaluate(
    context: platform.LocalAuthentication.LAContext,
    reason: String,
    allowDeviceCredentialFallback: Boolean,
    onResult: (Boolean) -> Unit,
) {
    // macOS defaults to DeviceOwnerAuthentication (Touch ID + password + Apple Watch) since many
    // Macs lack Touch ID; iOS defaults to biometrics-only. Credential fallback is opt-in on both.
    val policy = if (allowDeviceCredentialFallback) {
        platform.LocalAuthentication.LAPolicyDeviceOwnerAuthentication
    } else {
        platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics
    }
    context.evaluatePolicy(policy, localizedReason = reason) { success, _ ->
        CoroutineScope(Dispatchers.Main).launch { onResult(success) }
    }
}
