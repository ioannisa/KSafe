package eu.anifantakis.lib.ksafe.biometrics

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.SystemClock
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import eu.anifantakis.lib.ksafe.biometrics.BiometricHelper.activityWaitTimeoutMs
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import java.lang.ref.WeakReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Thrown when biometric authentication fails or is cancelled. */
class BiometricAuthException(message: String) : Exception(message)

/** Thrown when biometric authentication is required but no Activity is available. */
class BiometricActivityNotFoundException(message: String) : Exception(message)

/**
 * Tracks the current Activity and drives biometric authentication. Auto-initialized when
 * [KSafeBiometrics] is created with a Context, enabling zero-config use from ViewModels.
 * Prompt text comes from the call (see `KSafeBiometrics.verifyBiometric`).
 */
/**
 * Authenticator combination for a prompt that accepts device credentials.
 *
 * androidx rejects `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` on API 28-29 (see
 * `AuthenticatorUtils.isSupportedCombination`): `PromptInfo.build()` throws and
 * `canAuthenticate()` reports UNSUPPORTED, so on those two API levels the permissive prompt
 * could never be built and every call failed without ever showing UI. The library's own
 * guidance for that range is Class 2 (Weak); the effective bar is unchanged because the user
 * may satisfy this prompt with the device credential anyway. Biometrics-ONLY prompts keep
 * `BIOMETRIC_STRONG` on every API level.
 */
internal fun deviceCredentialAuthenticators(): Int =
    if (android.os.Build.VERSION.SDK_INT == android.os.Build.VERSION_CODES.P ||
        android.os.Build.VERSION.SDK_INT == android.os.Build.VERSION_CODES.Q
    ) {
        BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL
    } else {
        BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
    }

/**
 * Authenticators a call may satisfy. The prompt and the availability probe must ask about the
 * SAME set, or `biometricsAvailable` answers for a prompt that is never shown.
 */
internal fun allowedAuthenticators(allowDeviceCredentialFallback: Boolean): Int =
    if (allowDeviceCredentialFallback) {
        deviceCredentialAuthenticators()
    } else {
        BiometricManager.Authenticators.BIOMETRIC_STRONG
    }

object BiometricHelper {

    private var currentFragmentActivity: WeakReference<FragmentActivity>? = null
    private var currentAnyActivity: WeakReference<Activity>? = null
    private var isInitialized = false

    /** Process-wide guard so only one biometric prompt is ever in flight. */
    private val promptGate = BiometricPromptGate()

    private var createdFragmentActivity: WeakReference<FragmentActivity>? = null

    var activityWaitTimeoutMs: Long = 5_000L


    /**
     * Whether the user must explicitly confirm after biometric recognition. Only affects
     * weak/passive modalities (e.g. face); for `BIOMETRIC_STRONG` (fingerprint) the physical
     * action is the confirmation and this has no effect.
     */
    var confirmationRequired: Boolean = true

    internal var applicationContext: android.content.Context? = null
        private set

    /** Initialize activity tracking. Called automatically by [KSafeBiometrics]. */
    fun init(application: Application) {
        if (isInitialized) return
        isInitialized = true
        applicationContext = application.applicationContext

        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                // Fires during super.onCreate() (pre-STARTED), so tracking is available for ViewModel init.
                currentAnyActivity = WeakReference(activity)
                if (activity is FragmentActivity) {
                    createdFragmentActivity = WeakReference(activity)
                }
            }

            // Deliberately NOT shared with onActivityCreated, which tracks
            // createdFragmentActivity instead — a pre-STARTED activity is not foreground.
            fun trackForeground(activity: Activity) {
                currentAnyActivity = WeakReference(activity)
                if (activity is FragmentActivity) {
                    currentFragmentActivity = WeakReference(activity)
                }
            }

            override fun onActivityStarted(activity: Activity) = trackForeground(activity)

            override fun onActivityResumed(activity: Activity) = trackForeground(activity)

            override fun onActivityPaused(activity: Activity) {
                if (currentFragmentActivity?.get() == activity) {
                    currentFragmentActivity = null
                }
            }

            override fun onActivityStopped(activity: Activity) {
                if (currentAnyActivity?.get() == activity) {
                    currentAnyActivity = null
                }
            }

            override fun onActivityDestroyed(activity: Activity) {
                if (createdFragmentActivity?.get() == activity) {
                    createdFragmentActivity = null
                }
            }

            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
        })
    }

    fun getCurrentActivity(): FragmentActivity? = currentFragmentActivity?.get()

    /**
     * Best-effort synchronous probe for a usable [FragmentActivity]. Reports false for a plain
     * `ComponentActivity` host (Compose default) rather than the false-positive `canAuthenticate`
     * gives, which would make every `authenticate()` hang to timeout; fail-closed. The reflection
     * probe primes the weak-ref cache for a subsequent authenticate().
     */
    fun hasUsableFragmentActivity(): Boolean =
        currentFragmentActivity?.get() != null ||
            createdFragmentActivity?.get() != null ||
            findCurrentActivity() != null

    private suspend fun waitForFragmentActivity(): FragmentActivity? {
        currentFragmentActivity?.get()?.let { return it }

        // Fallback when callbacks missed the activity (KSafe initialized after it reached RESUMED).
        findCurrentActivity()?.let { return it }

        val createdActivity = createdFragmentActivity?.get()
        if (createdActivity != null) {
            return waitForActivityStarted(createdActivity)
        }

        // Monotonic (like the authorization TTLs): a wall-clock jump must not cut the
        // activity wait short or stretch it.
        val startTime = SystemClock.elapsedRealtime()
        val pollIntervalMs = 50L

        while (SystemClock.elapsedRealtime() - startTime < activityWaitTimeoutMs) {
            currentFragmentActivity?.get()?.let { return it }
            createdFragmentActivity?.get()?.let { activity ->
                return waitForActivityStarted(activity)
            }
            delay(pollIntervalMs)
        }

        return currentFragmentActivity?.get()
    }

    // Reflection over ActivityThread for the case where init() ran after the Activity reached
    // RESUMED (common with lazy DI) so no lifecycle callback fired.
    private fun findCurrentActivity(): FragmentActivity? {
        try {
            val activityThread = Class.forName("android.app.ActivityThread")
                .getMethod("currentActivityThread").invoke(null) ?: return null
            val field = activityThread.javaClass.getDeclaredField("mActivities")
            field.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val activities = field.get(activityThread) as? Map<Any, Any> ?: return null
            for (record in activities.values) {
                val recordClass = record.javaClass
                val pausedField = recordClass.getDeclaredField("paused")
                pausedField.isAccessible = true
                if (!pausedField.getBoolean(record)) {
                    val activityField = recordClass.getDeclaredField("activity")
                    activityField.isAccessible = true
                    val activity = activityField.get(record) as? Activity ?: continue
                    if (activity is FragmentActivity && !activity.isDestroyed && !activity.isFinishing) {
                        currentFragmentActivity = WeakReference(activity)
                        createdFragmentActivity = WeakReference(activity)
                        currentAnyActivity = WeakReference(activity)
                        return activity
                    }
                }
            }
        } catch (_: Exception) {
            // Reflection may fail on some OEM/Android versions; polling remains as fallback.
        }
        return null
    }

    // BiometricPrompt requires the host to be at least STARTED.
    private suspend fun waitForActivityStarted(activity: FragmentActivity): FragmentActivity? {
        if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            return activity
        }

        return try {
            withTimeout(activityWaitTimeoutMs) {
                suspendCancellableCoroutine { continuation ->
                    val observer = object : LifecycleEventObserver {
                        override fun onStateChanged(source: androidx.lifecycle.LifecycleOwner, event: Lifecycle.Event) {
                            if (event == Lifecycle.Event.ON_START || event == Lifecycle.Event.ON_RESUME) {
                                source.lifecycle.removeObserver(this)
                                if (continuation.isActive) {
                                    continuation.resume(activity)
                                }
                            } else if (event == Lifecycle.Event.ON_DESTROY) {
                                source.lifecycle.removeObserver(this)
                                if (continuation.isActive) {
                                    continuation.resume(null)
                                }
                            }
                        }
                    }

                    // Lifecycle must be touched on the main thread; re-check state after posting.
                    activity.runOnUiThread {
                        if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                            if (continuation.isActive) {
                                continuation.resume(activity)
                            }
                        } else if (activity.lifecycle.currentState == Lifecycle.State.DESTROYED) {
                            if (continuation.isActive) {
                                continuation.resume(null)
                            }
                        } else {
                            activity.lifecycle.addObserver(observer)

                            continuation.invokeOnCancellation {
                                activity.runOnUiThread {
                                    activity.lifecycle.removeObserver(observer)
                                }
                            }
                        }
                    }
                }
            }
        } catch (e: TimeoutCancellationException) {
            null
        }
    }

    /**
     * Suspends until authentication resolves, waiting up to [activityWaitTimeoutMs] for an Activity.
     * Must NOT be called from the Main thread (deadlocks). Returns true if it prompted, false if
     * [skipIfAuthorized] (re-checked once the single-prompt gate is held) reported a fresh
     * authorization and the prompt was skipped.
     *
     * @param allowDeviceCredentialFallback `true` accepts PIN/password fallback
     *        (`BIOMETRIC_STRONG | DEVICE_CREDENTIAL`); `false` is biometrics-only with a Cancel button.
     * @throws BiometricActivityNotFoundException if no FragmentActivity becomes available within timeout
     * @throws BiometricAuthException if authentication fails or is cancelled
     */
    suspend fun authenticate(
        subtitle: String,
        allowDeviceCredentialFallback: Boolean = true,
        title: String? = null,
        cancelLabel: String? = null,
        skipIfAuthorized: () -> Boolean = { false },
    ): Boolean {
        val fragmentActivity = waitForFragmentActivity()

        if (fragmentActivity == null) {
            val anyActivity = currentAnyActivity?.get()
            if (anyActivity != null) {
                throw BiometricActivityNotFoundException(
                    "BiometricPrompt requires FragmentActivity or AppCompatActivity. " +
                    "Your current Activity (${anyActivity::class.simpleName}) is not a FragmentActivity. " +
                    "Change your MainActivity to extend AppCompatActivity instead of ComponentActivity."
                )
            } else {
                throw BiometricActivityNotFoundException(
                    "No Activity available for biometric prompt after waiting ${activityWaitTimeoutMs}ms. " +
                    "Ensure you're accessing biometric-protected data while an Activity is visible."
                )
            }
        }

        // Serialize prompts: a second concurrent prompt would overwrite the shared
        // activity-scoped callback and strand the first caller's coroutine forever. The gate
        // queues concurrent callers; the activity wait above stays outside it.
        return promptGate.withSinglePrompt {
            // Re-check inside the gate: a caller queued ahead may have just seeded a fresh
            // authorization, letting us skip a redundant back-to-back prompt.
            if (skipIfAuthorized()) return@withSinglePrompt false
            showBiometricPrompt(fragmentActivity, subtitle, allowDeviceCredentialFallback, title, cancelLabel)
            true
        }
    }

    private suspend fun showBiometricPrompt(
        activity: FragmentActivity,
        subtitle: String,
        allowDeviceCredentialFallback: Boolean,
        title: String?,
        cancelLabel: String?,
    ): Unit = suspendCancellableCoroutine { continuation ->
        // BiometricPrompt must be created and shown on the main thread.
        activity.runOnUiThread {
            try {
                val executor = ContextCompat.getMainExecutor(activity)

                val biometricPrompt = BiometricPrompt(
                    activity,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (continuation.isActive) {
                                continuation.resume(Unit)
                            }
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            if (continuation.isActive) {
                                continuation.resumeWithException(
                                    BiometricAuthException("Authentication error: $errString")
                                )
                            }
                        }

                        override fun onAuthenticationFailed() {
                            // A single rejected attempt; the prompt stays open for retry.
                        }
                    }
                )

                // PromptInfo REQUIRES a title. Falling back to the app's own launcher label
                // (already localized by the app) beats any string we could hardcode here.
                val resolvedTitle = promptTextOrNull(title)
                    ?: activity.applicationInfo.loadLabel(activity.packageManager).toString()
                // android.R.string.cancel is translated by the platform in every system
                // language — a literal "Cancel" would ship English to every locale.
                val resolvedCancel = promptTextOrNull(cancelLabel)
                    ?: activity.getString(android.R.string.cancel)

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(resolvedTitle)
                    .setSubtitle(subtitle)
                    .setConfirmationRequired(confirmationRequired)
                    .setAllowedAuthenticators(allowedAuthenticators(allowDeviceCredentialFallback))
                    // DEVICE_CREDENTIAL cannot coexist with a negative button; biometrics-only
                    // mode must supply one so the user can dismiss the prompt.
                    .apply { if (!allowDeviceCredentialFallback) setNegativeButtonText(resolvedCancel) }
                    .build()

                biometricPrompt.authenticate(promptInfo)

                // Dismiss on cancellation (main thread): androidx.biometric reuses ONE
                // activity-scoped fragment, so an orphaned prompt would rebind to the next caller
                // and could be satisfied under the wrong security config (e.g. device-credential
                // fallback the next caller refused).
                continuation.invokeOnCancellation {
                    activity.runOnUiThread { runCatching { biometricPrompt.cancelAuthentication() } }
                }

            } catch (e: Exception) {
                if (continuation.isActive) {
                    continuation.resumeWithException(
                        BiometricAuthException("Failed to show biometric prompt: ${e.message}")
                    )
                }
            }
        }
    }
}
