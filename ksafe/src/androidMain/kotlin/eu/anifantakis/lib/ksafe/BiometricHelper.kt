package eu.anifantakis.lib.ksafe

import android.app.Activity
import android.app.Application
import android.os.Bundle
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import java.lang.ref.WeakReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Exception thrown when biometric authentication fails or is cancelled.
 */
class BiometricAuthException(message: String) : Exception(message)

/**
 * Exception thrown when biometric authentication is required but no Activity is available.
 */
class BiometricActivityNotFoundException(message: String) : Exception(message)

/**
 * Helper object that tracks the current Activity and handles biometric authentication.
 *
 * This is initialized automatically when KSafe is created with a Context.
 * It enables zero-config biometric support for property delegation.
 *
 * You can customize the biometric prompt text:
 * ```kotlin
 * BiometricHelper.promptTitle = "Unlock Secure Data"
 * ```
 */
object BiometricHelper {

    private var currentFragmentActivity: WeakReference<FragmentActivity>? = null
    private var currentAnyActivity: WeakReference<Activity>? = null
    private var isInitialized = false

    /**
     * Track activities from onCreate so they're available during ViewModel initialization.
     * These may not yet be in STARTED state.
     */
    private var createdFragmentActivity: WeakReference<FragmentActivity>? = null

    /**
     * Timeout in milliseconds to wait for an Activity to become available.
     * Default is 5 seconds - covers most app startup scenarios.
     */
    var activityWaitTimeoutMs: Long = 5_000L

    /**
     * Biometric prompt configuration. Can be customized by the app.
     */
    var promptTitle: String = "Authentication Required"
    // Subtitle is now passed dynamically per-call, but we keep this as a default fallback
    var promptSubtitle: String = "Authenticate to access secure data"

    /**
     * Whether users must explicitly confirm after successful biometric recognition.
     * Keep `true` for sensitive actions; set `false` to allow faster passive-auth flows.
     */
    var confirmationRequired: Boolean = true

    /**
     * Initialize activity tracking. Called automatically by KSafe.
     */
    fun init(application: Application) {
        if (isInitialized) return
        isInitialized = true

        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                // Track FragmentActivity early - this fires during super.onCreate()
                // before setContent { } runs, so it's available for ViewModel initialization
                currentAnyActivity = WeakReference(activity)
                if (activity is FragmentActivity) {
                    createdFragmentActivity = WeakReference(activity)
                }
            }

            override fun onActivityStarted(activity: Activity) {
                // Activity is now in STARTED state - can show BiometricPrompt
                currentAnyActivity = WeakReference(activity)
                if (activity is FragmentActivity) {
                    currentFragmentActivity = WeakReference(activity)
                }
            }

            override fun onActivityResumed(activity: Activity) {
                currentAnyActivity = WeakReference(activity)
                if (activity is FragmentActivity) {
                    currentFragmentActivity = WeakReference(activity)
                }
            }

            override fun onActivityPaused(activity: Activity) {
                // Clear resumed reference
                if (currentFragmentActivity?.get() == activity) {
                    currentFragmentActivity = null
                }
            }

            override fun onActivityStopped(activity: Activity) {
                // Clear started reference
                if (currentAnyActivity?.get() == activity) {
                    currentAnyActivity = null
                }
            }

            override fun onActivityDestroyed(activity: Activity) {
                // Clear created reference
                if (createdFragmentActivity?.get() == activity) {
                    createdFragmentActivity = null
                }
            }

            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
        })
    }

    /**
     * Get the currently resumed FragmentActivity, or null if none available.
     */
    fun getCurrentActivity(): FragmentActivity? = currentFragmentActivity?.get()

    /**
     * Wait for a FragmentActivity in STARTED state to become available.
     * If we have a CREATED activity, wait for it to reach STARTED.
     * Returns null if timeout expires.
     */
    private suspend fun waitForFragmentActivity(): FragmentActivity? {
        // First check if we already have a STARTED FragmentActivity
        currentFragmentActivity?.get()?.let { return it }

        // Check if we have a CREATED activity that will reach STARTED soon
        val createdActivity = createdFragmentActivity?.get()
        if (createdActivity != null) {
            // Wait for this activity to reach STARTED state
            return waitForActivityStarted(createdActivity)
        }

        // No activity at all - poll for one to appear
        val startTime = System.currentTimeMillis()
        val pollIntervalMs = 50L

        while (System.currentTimeMillis() - startTime < activityWaitTimeoutMs) {
            // Check if a STARTED Activity is now available
            currentFragmentActivity?.get()?.let { return it }

            // Check if a CREATED activity appeared
            createdFragmentActivity?.get()?.let { activity ->
                return waitForActivityStarted(activity)
            }

            delay(pollIntervalMs)
        }

        return currentFragmentActivity?.get()
    }

    /**
     * Wait for a specific FragmentActivity to reach STARTED state.
     * BiometricPrompt requires the activity to be at least STARTED.
     */
    private suspend fun waitForActivityStarted(activity: FragmentActivity): FragmentActivity? {
        // Check if already started
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

                    // Add observer on main thread
                    activity.runOnUiThread {
                        // Double-check state after posting to main thread
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
                            
                            // Remove observer on cancellation
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
     * Authenticate the user with biometrics/device credential.
     *
     * This suspends until authentication succeeds or fails.
     * If no Activity is immediately available, waits up to [activityWaitTimeoutMs] for one.
     * Must NOT be called from the Main thread (will deadlock).
     *
     * @param subtitle The subtitle to display in the prompt.
     * @throws BiometricActivityNotFoundException if no FragmentActivity becomes available within timeout
     * @throws BiometricAuthException if authentication fails or is cancelled
     */
    suspend fun authenticate(subtitle: String = promptSubtitle) {
        val fragmentActivity = waitForFragmentActivity()

        if (fragmentActivity == null) {
            // Check if there's a non-FragmentActivity visible - provide helpful error
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

        // Now show the biometric prompt
        showBiometricPrompt(fragmentActivity, subtitle)
    }

    /**
     * Shows the BiometricPrompt on the given activity.
     */
    private suspend fun showBiometricPrompt(activity: FragmentActivity, subtitle: String): Unit = suspendCancellableCoroutine { continuation ->
        // BiometricPrompt must be created and shown on the main thread
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
                            // Don't fail the continuation - user can retry
                            // The prompt stays open for retry
                        }
                    }
                )

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(promptTitle)
                    .setSubtitle(subtitle)
                    .setConfirmationRequired(confirmationRequired)
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                    .build()

                biometricPrompt.authenticate(promptInfo)

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
