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

// androidx rejects STRONG or DEVICE_CREDENTIAL on API 28-29 (build() throws, canAuthenticate
// reports UNSUPPORTED), so those levels use Weak; the credential fallback keeps the bar.
internal fun deviceCredentialAuthenticators(): Int =
    if (android.os.Build.VERSION.SDK_INT == android.os.Build.VERSION_CODES.P ||
        android.os.Build.VERSION.SDK_INT == android.os.Build.VERSION_CODES.Q
    ) {
        BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL
    } else {
        BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
    }

// Probe and prompt must ask the same set, or availability answers for a prompt never shown.
internal fun allowedAuthenticators(allowDeviceCredentialFallback: Boolean): Int =
    if (allowDeviceCredentialFallback) {
        deviceCredentialAuthenticators()
    } else {
        BiometricManager.Authenticators.BIOMETRIC_STRONG
    }

/**
 * Android prompt driver behind [KSafeBiometrics]: tracks the foreground `FragmentActivity` and
 * shows `BiometricPrompt` on it. Initialized at app startup by the library's manifest content
 * provider, so apps touch it only to tune [activityWaitTimeoutMs] / [confirmationRequired], or
 * to call [authenticate] directly for its typed exceptions instead of a plain `false`.
 */
object BiometricHelper {

    private const val BIOMETRIC_FRAGMENT_TAG = "androidx.biometric.BiometricFragment"

    private var currentFragmentActivity: WeakReference<FragmentActivity>? = null
    private var currentAnyActivity: WeakReference<Activity>? = null
    private var isInitialized = false

    private val promptGate = BiometricPromptGate()

    private var createdFragmentActivity: WeakReference<FragmentActivity>? = null

    /** How long [authenticate] waits for a started `FragmentActivity` before throwing
     *  [BiometricActivityNotFoundException]. */
    var activityWaitTimeoutMs: Long = 5_000L


    /** Whether the user must confirm after recognition. Only affects passive modalities like face. */
    var confirmationRequired: Boolean = true

    internal var applicationContext: android.content.Context? = null
        private set

    /** Starts activity tracking. Runs automatically at app startup through the library's manifest
     *  `<provider>`; call it yourself only if that provider was removed. Repeat calls are no-ops. */
    fun init(application: Application) {
        if (isInitialized) return
        isInitialized = true
        applicationContext = application.applicationContext

        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                currentAnyActivity = WeakReference(activity)
                if (activity is FragmentActivity) {
                    createdFragmentActivity = WeakReference(activity)
                }
            }

            // Not shared with onActivityCreated: a pre-STARTED activity is not foreground.
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

    /** The started or resumed `FragmentActivity` being tracked, or `null` while none is in the foreground. */
    fun getCurrentActivity(): FragmentActivity? = currentFragmentActivity?.get()

    internal fun setForegroundActivityForTest(activity: FragmentActivity?) {
        currentFragmentActivity = activity?.let { WeakReference(it) }
    }

    internal var beforePromptShowForTest: (() -> Unit)? = null

    /**
     * Whether a [FragmentActivity] can host a prompt. Fail-closed: false for a plain
     * `ComponentActivity`, where `canAuthenticate` still says yes and every prompt would time out.
     */
    fun hasUsableFragmentActivity(): Boolean =
        currentFragmentActivity?.get() != null ||
            createdFragmentActivity?.get() != null ||
            findCurrentActivity() != null

    private suspend fun waitForFragmentActivity(): FragmentActivity? {
        currentFragmentActivity?.get()?.let { return it }

        findCurrentActivity()?.let { return it }

        val createdActivity = createdFragmentActivity?.get()
        if (createdActivity != null) {
            return waitForActivityStarted(createdActivity)
        }

        // Monotonic: a wall-clock jump must not cut the wait short or stretch it.
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

    // Covers init() running after the Activity reached RESUMED, where no callback ever fires for it.
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
            // Reflection may fail on some OEMs; the poll above is the fallback.
        }
        return null
    }

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
     * Shows the system prompt and suspends until it resolves, waiting up to [activityWaitTimeoutMs]
     * for a started `FragmentActivity` first. Callable from any dispatcher, Main included; never
     * wrap it in `runBlocking` on the main thread, where the prompt callbacks arrive. Concurrent
     * callers queue behind one prompt. Cancelling the caller dismisses the prompt.
     *
     * @param subtitle Text under the title; the reason the user is being asked.
     * @param allowDeviceCredentialFallback `true` also accepts PIN/pattern/password; `false` is
     *        biometrics-only and adds a cancel button.
     * @param title Prompt title; `null` or blank shows the app label.
     * @param cancelLabel Cancel button text, used only when the fallback is off; `null` or blank
     *        shows the system's localized Cancel.
     * @param skipIfAuthorized Re-checked once this call holds the prompt slot; `true` skips the prompt.
     * @param onAuthorized Runs after a successful prompt, before the slot is released.
     * @return `true` after a successful prompt; `false` when [skipIfAuthorized] skipped it.
     * @throws BiometricActivityNotFoundException if no `FragmentActivity` appears within the timeout
     * @throws BiometricAuthException if authentication fails, is dismissed, or no prompt can be shown
     */
    suspend fun authenticate(
        subtitle: String,
        allowDeviceCredentialFallback: Boolean = true,
        title: String? = null,
        cancelLabel: String? = null,
        skipIfAuthorized: () -> Boolean = { false },
        onAuthorized: suspend () -> Unit = {},
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

        // A second concurrent prompt would overwrite the shared activity-scoped callback and
        // strand the first caller forever. The activity wait above stays outside the gate.
        return promptGate.withSinglePrompt {
            if (skipIfAuthorized()) return@withSinglePrompt false
            showBiometricPrompt(fragmentActivity, subtitle, allowDeviceCredentialFallback, title, cancelLabel)
            // Record while the gate is still held: a caller queued behind re-checks
            // skipIfAuthorized the instant it changes hands, and would prompt again.
            onAuthorized()
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
        activity.runOnUiThread {
            // A cancellation that landed while this sat in the main queue must not raise the sheet.
            if (!continuation.isActive) return@runOnUiThread
            try {
                val executor = ContextCompat.getMainExecutor(activity)

                var promptRef: BiometricPrompt? = null
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
                            // One rejected attempt; the prompt stays open for a retry.
                        }
                    }
                )

                // PromptInfo requires a title; both fallbacks arrive already localized.
                val resolvedTitle = promptTextOrNull(title)
                    ?: activity.applicationInfo.loadLabel(activity.packageManager).toString()
                val resolvedCancel = promptTextOrNull(cancelLabel)
                    ?: activity.getString(android.R.string.cancel)

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(resolvedTitle)
                    .setSubtitle(subtitle)
                    .setConfirmationRequired(confirmationRequired)
                    .setAllowedAuthenticators(allowedAuthenticators(allowDeviceCredentialFallback))
                    // DEVICE_CREDENTIAL cannot coexist with a negative button; biometrics-only needs one.
                    .apply { if (!allowDeviceCredentialFallback) setNegativeButtonText(resolvedCancel) }
                    .build()

                // androidx drops the prompt silently once the FragmentManager state is saved, so a
                // host that stopped while we queued on the gate would hang the caller forever.
                if (activity.isFinishing || activity.isDestroyed ||
                    activity.supportFragmentManager.isStateSaved() ||
                    !activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
                ) {
                    continuation.resumeWithException(
                        BiometricAuthException("Activity is not in a state to show a biometric prompt")
                    )
                    return@runOnUiThread
                }

                // androidx.biometric reuses one activity-scoped fragment, so an orphaned prompt
                // rebinds to the next caller under a config that caller refused. Registered before
                // the show, with promptRef still null, so an early fire touches nobody else's prompt.
                continuation.invokeOnCancellation {
                    activity.runOnUiThread { runCatching { promptRef?.cancelAuthentication() } }
                }
                promptRef = biometricPrompt
                if (!continuation.isActive) return@runOnUiThread

                beforePromptShowForTest?.invoke()
                biometricPrompt.authenticate(promptInfo)

                // androidx attaches the fragment synchronously, so its absence means a dropped prompt.
                if (continuation.isActive &&
                    activity.supportFragmentManager.findFragmentByTag(BIOMETRIC_FRAGMENT_TAG) == null
                ) {
                    runCatching { biometricPrompt.cancelAuthentication() }
                    continuation.resumeWithException(
                        BiometricAuthException("Biometric prompt was not attached")
                    )
                    return@runOnUiThread
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
