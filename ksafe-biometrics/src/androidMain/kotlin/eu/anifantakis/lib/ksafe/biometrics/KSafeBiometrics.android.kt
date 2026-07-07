package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicReference

// Android [KSafeBiometrics] platform helpers, backed by real `BiometricPrompt`
// (BIOMETRIC_STRONG + DEVICE_CREDENTIAL). Activity tracking is bootstrapped by
// [KSafeBiometricsInitProvider] at startup — no consumer init required.

// Per-scope last-success timestamp; lets verify-paths skip the prompt while a caller-supplied
// [BiometricAuthorizationDuration] is still valid for the scope.
private val biometricAuthSessions = AtomicReference<Map<String, Long>>(emptyMap())

// TTL clock: must never go backward (a wall-clock jump mustn't extend an authorization) and
// must keep counting during sleep (else a "60s" window survives deep sleep). nanoTime() freezes
// on SoC suspend, so use elapsedRealtime() (CLOCK_BOOTTIME).
private fun monotonicNowMs(): Long = SystemClock.elapsedRealtime()

// Strict (biometrics-only) authorizations cache under a separate slot so a device-credential
// (PIN/password) success can never satisfy a later allowDeviceCredentialFallback = false call
// within the window. The injective strength discriminator lives in BiometricAuthSession.sessionKey.
private fun sessionKeyFor(rawScope: String?, allowDeviceCredentialFallback: Boolean): String =
    BiometricAuthSession.sessionKey(rawScope, requireStrict = !allowDeviceCredentialFallback)

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
    allowDeviceCredentialFallback: Boolean,
): Boolean {
    if (BiometricAuthSession.shouldCache(authorizationDuration)) {
        val scope = sessionKeyFor(authorizationDuration!!.scope, allowDeviceCredentialFallback)
        val lastAuth = biometricAuthSessions.get()[scope] ?: 0L
        val now = monotonicNowMs()
        if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
            return true
        }
    }

    return try {
        BiometricHelper.authenticate(reason, allowDeviceCredentialFallback)
        // Seed the cache only when caching was opted into (duration > 0) and the caller's
        // coroutine is still active — caching after cancellation would grant a later call a
        // prompt-free pass off an authorization the caller never actually received.
        if (BiometricAuthSession.shouldCache(authorizationDuration)) {
            seedBiometricSessionIfActive {
                updateBiometricSession(
                    sessionKeyFor(authorizationDuration!!.scope, allowDeviceCredentialFallback),
                    monotonicNowMs(),
                )
            }
        }
        true
    } catch (e: BiometricAuthException) {
        println("KSafeBiometrics: Biometric authentication failed - ${e.message}")
        false
    } catch (e: BiometricActivityNotFoundException) {
        println("KSafeBiometrics: Biometric Activity not found - ${e.message}")
        false
    } catch (e: CancellationException) {
        // Cancellation is not an auth failure — rethrow so structured concurrency works
        // (a cancelled scope must not silently see `false` = "denied"). Must precede the
        // generic catch, since CancellationException is an Exception.
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
    onResult: (Boolean) -> Unit,
) {
    CoroutineScope(Dispatchers.Default + SupervisorJob()).launch {
        val ok = platformVerifyBiometric(reason, authorizationDuration, allowDeviceCredentialFallback)
        // Deliver on the main thread (matching Apple): the verify coroutine runs on
        // Dispatchers.Default, so a View-based consumer touching UI in the callback would crash.
        Handler(Looper.getMainLooper()).post { onResult(ok) }
    }
}

internal actual fun platformClearBiometricAuth(scope: String?) {
    if (scope == null) {
        biometricAuthSessions.set(emptyMap())
        return
    }
    // Clear both the permissive and strict slots for this scope (see [sessionKeyFor]).
    val permissiveKey = sessionKeyFor(scope, allowDeviceCredentialFallback = true)
    val strictKey = sessionKeyFor(scope, allowDeviceCredentialFallback = false)
    while (true) {
        val current = biometricAuthSessions.get()
        val updated = current - permissiveKey - strictKey
        if (biometricAuthSessions.compareAndSet(current, updated)) break
    }
}
