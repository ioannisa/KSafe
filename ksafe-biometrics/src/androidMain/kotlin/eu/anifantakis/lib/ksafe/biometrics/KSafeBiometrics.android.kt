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

// Clock for the authorization TTL. Requirements: (a) never go backward — a
// backward wall-clock jump (NTP correction, manual/timezone change) must not
// extend a cached authorization; (b) count time while the device is asleep —
// otherwise a "60s" window becomes "60s of awake time" and survives arbitrarily
// long deep sleep (a pocketed phone), silently honoring expired authorization
// (deep-review #13). `System.nanoTime()` / `TimeSource.Monotonic` satisfies (a)
// but NOT (b): it freezes while the SoC is suspended. `SystemClock.elapsedRealtime()`
// (CLOCK_BOOTTIME) satisfies both — monotonic AND suspend-inclusive.
private fun monotonicNowMs(): Long = SystemClock.elapsedRealtime()

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
    if (authorizationDuration != null && authorizationDuration.duration > 0) {
        val scope = authorizationDuration.scope ?: ""
        val lastAuth = biometricAuthSessions.get()[scope] ?: 0L
        val now = monotonicNowMs()
        if (lastAuth > 0 && (now - lastAuth) < authorizationDuration.duration) {
            return true
        }
    }

    return try {
        BiometricHelper.authenticate(reason, allowDeviceCredentialFallback)
        if (authorizationDuration != null) {
            updateBiometricSession(authorizationDuration.scope ?: "", monotonicNowMs())
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
        // Deliver onResult on the MAIN thread, matching the Apple implementation. The verify
        // coroutine runs on Dispatchers.Default, so without this the callback fires on a
        // background thread — a View-based consumer that touches the UI from it crashes
        // ("Only the original thread that created a view hierarchy can touch its views",
        // deep-review #39). Compose consumers happen to be tolerant; View ones are not.
        Handler(Looper.getMainLooper()).post { onResult(ok) }
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
