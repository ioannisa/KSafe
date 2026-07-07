package eu.anifantakis.lib.ksafe.biometrics

import android.app.Activity
import android.app.Application
import android.os.Bundle
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
 * Prompt text is customizable via [promptTitle] / [promptSubtitle].
 */
object BiometricHelper {

    private var currentFragmentActivity: WeakReference<FragmentActivity>? = null
    private var currentAnyActivity: WeakReference<Activity>? = null
    private var isInitialized = false

    /** Process-wide guard so only one biometric prompt is ever in flight. */
    private val promptGate = BiometricPromptGate()

    // Tracked from onCreate (may be pre-STARTED) so it's available during ViewModel init.
    private var createdFragmentActivity: WeakReference<FragmentActivity>? = null

    /** How long to wait for an Activity to become available. */
    var activityWaitTimeoutMs: Long = 5_000L

    var promptTitle: String = "Authentication Required"
    // Default fallback; the subtitle is normally passed per-call.
    var promptSubtitle: String = "Authenticate to access secure data"

    /**
     * Whether the user must explicitly confirm after biometric recognition. Only affects
     * weak/passive modalities (e.g. face); for `BIOMETRIC_STRONG` (fingerprint) the physical
     * action is the confirmation and this has no effect.
     */
    var confirmationRequired: Boolean = true

    /** Initialize activity tracking. Called automatically by [KSafeBiometrics]. */
    fun init(application: Application) {
        if (isInitialized) return
        isInitialized = true

        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                // Fires during super.onCreate(), before setContent {}, so it's available for
                // ViewModel init — even though the activity isn't STARTED yet.
                currentAnyActivity = WeakReference(activity)
                if (activity is FragmentActivity) {
                    createdFragmentActivity = WeakReference(activity)
                }
            }

            override fun onActivityStarted(activity: Activity) {
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

    /** The currently resumed FragmentActivity, or null if none available. */
    fun getCurrentActivity(): FragmentActivity? = currentFragmentActivity?.get()

    // Waits (up to [activityWaitTimeoutMs]) for a STARTED FragmentActivity, needed before a
    // BiometricPrompt can show. Returns null on timeout.
    private suspend fun waitForFragmentActivity(): FragmentActivity? {
        currentFragmentActivity?.get()?.let { return it }

        // Fallback for when lifecycle callbacks missed the current activity (e.g. KSafe was
        // initialized after it already reached RESUMED): find it via ActivityThread.
        findCurrentActivity()?.let { return it }

        val createdActivity = createdFragmentActivity?.get()
        if (createdActivity != null) {
            return waitForActivityStarted(createdActivity)
        }

        val startTime = System.currentTimeMillis()
        val pollIntervalMs = 50L

        while (System.currentTimeMillis() - startTime < activityWaitTimeoutMs) {
            currentFragmentActivity?.get()?.let { return it }
            createdFragmentActivity?.get()?.let { activity ->
                return waitForActivityStarted(activity)
            }
            delay(pollIntervalMs)
        }

        return currentFragmentActivity?.get()
    }

    // Finds the resumed FragmentActivity via ActivityThread reflection, covering the case where
    // init() ran after the Activity reached RESUMED (common with lazy DI) so no callback fired.
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
                        // Cache so lifecycle callbacks track it going forward.
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

    // Waits for a specific FragmentActivity to reach STARTED, which BiometricPrompt requires.
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
     * Suspends until biometric authentication succeeds or fails, waiting up to
     * [activityWaitTimeoutMs] for an Activity. Must NOT be called from the Main thread (deadlocks).
     *
     * @param allowDeviceCredentialFallback `true` accepts PIN/password fallback
     *        (`BIOMETRIC_STRONG | DEVICE_CREDENTIAL`); `false` is biometrics-only with a Cancel button.
     * @throws BiometricActivityNotFoundException if no FragmentActivity becomes available within timeout
     * @throws BiometricAuthException if authentication fails or is cancelled
     */
    suspend fun authenticate(
        subtitle: String = promptSubtitle,
        allowDeviceCredentialFallback: Boolean = true,
    ) {
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
        promptGate.withSinglePrompt {
            showBiometricPrompt(fragmentActivity, subtitle, allowDeviceCredentialFallback)
        }
    }

    private suspend fun showBiometricPrompt(
        activity: FragmentActivity,
        subtitle: String,
        allowDeviceCredentialFallback: Boolean,
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

                // DEVICE_CREDENTIAL cannot coexist with a negative button; biometrics-only
                // mode must supply one so the user can dismiss the prompt.
                val promptInfo = if (allowDeviceCredentialFallback) {
                    BiometricPrompt.PromptInfo.Builder()
                        .setTitle(promptTitle)
                        .setSubtitle(subtitle)
                        .setConfirmationRequired(confirmationRequired)
                        .setAllowedAuthenticators(
                            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
                        )
                        .build()
                } else {
                    BiometricPrompt.PromptInfo.Builder()
                        .setTitle(promptTitle)
                        .setSubtitle(subtitle)
                        .setConfirmationRequired(confirmationRequired)
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        .setNegativeButtonText("Cancel")
                        .build()
                }

                biometricPrompt.authenticate(promptInfo)

                // Dismiss the prompt if the caller's coroutine is cancelled. androidx.biometric
                // reuses ONE activity-scoped fragment, so an orphaned prompt would rebind to the
                // next caller and could be satisfied under the wrong security config (e.g. offering
                // device-credential fallback the next caller refused). Must run on the main thread.
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
