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

// Clock for the authorization TTL. Must (a) never go backward — a wall-clock
// jump must not extend a cached authorization — and (b) keep counting while the
// device is asleep, or a "60s" window survives arbitrary deep sleep.
// `System.nanoTime()` satisfies (a) but freezes during SoC suspend;
// `SystemClock.elapsedRealtime()` (CLOCK_BOOTTIME) satisfies both.
private fun monotonicNowMs(): Long = SystemClock.elapsedRealtime()

// Strict (biometrics-only) authorizations are cached under a separate slot so a
// device-credential (PIN/password) success can NEVER satisfy a later
// allowDeviceCredentialFallback = false call within the window (deep-review L3). The
// injective strength discriminator lives in the shared BiometricAuthSession.sessionKey
// (round-3 audit R3 — the old "$base|strict" suffix was NOT injective).
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
        // Only seed the cache when the caller opted into caching (duration > 0);
        // recording an opt-out call would let a later, longer-window call reuse
        // it without a prompt.
        if (BiometricAuthSession.shouldCache(authorizationDuration)) {
            updateBiometricSession(
                sessionKeyFor(authorizationDuration!!.scope, allowDeviceCredentialFallback),
                monotonicNowMs(),
            )
        }
        true
    } catch (e: BiometricAuthException) {
        println("KSafeBiometrics: Biometric authentication failed - ${e.message}")
        false
    } catch (e: BiometricActivityNotFoundException) {
        println("KSafeBiometrics: Biometric Activity not found - ${e.message}")
        false
    } catch (e: CancellationException) {
        // The caller's coroutine was cancelled while the prompt was in flight.
        // Cancellation is NOT an auth failure — rethrow so structured concurrency
        // works (otherwise a cancelled scope silently sees `false` = "denied").
        // CancellationException is an Exception, so this MUST precede the generic catch.
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
        // Deliver onResult on the main thread, matching the Apple implementation.
        // The verify coroutine runs on Dispatchers.Default; a View-based consumer
        // that touches the UI from the callback would crash otherwise.
        Handler(Looper.getMainLooper()).post { onResult(ok) }
    }
}

internal actual fun platformClearBiometricAuth(scope: String?) {
    if (scope == null) {
        biometricAuthSessions.set(emptyMap())
        return
    }
    // Clear BOTH the permissive and strict slots for this scope (see [sessionKeyFor]).
    val permissiveKey = sessionKeyFor(scope, allowDeviceCredentialFallback = true)
    val strictKey = sessionKeyFor(scope, allowDeviceCredentialFallback = false)
    while (true) {
        val current = biometricAuthSessions.get()
        val updated = current - permissiveKey - strictKey
        if (biometricAuthSessions.compareAndSet(current, updated)) break
    }
}
