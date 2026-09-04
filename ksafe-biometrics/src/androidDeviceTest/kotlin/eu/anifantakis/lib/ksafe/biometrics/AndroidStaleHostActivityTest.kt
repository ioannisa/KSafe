package eu.anifantakis.lib.ksafe.biometrics

import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Host for the stale-activity case; never shown past CREATED. */
class StaleHostActivity : FragmentActivity()

/**
 * Locks in: a prompt requested for an Activity that has since stopped fails fast instead of
 * hanging. androidx's `BiometricPrompt.authenticateInternal` returns silently when the host
 * FragmentManager `isStateSaved()`, so no callback ever fires and the caller would suspend
 * forever holding the process-wide prompt gate.
 *
 * Needs no enrolled biometric and shows no UI, so it runs unattended on an emulator.
 */
@RunWith(AndroidJUnit4::class)
class AndroidStaleHostActivityTest {

    @Test
    fun stoppedHost_failsFast_insteadOfHanging() {
        val scenario = ActivityScenario.launch(StaleHostActivity::class.java)
        try {
            // CREATED runs onPause/onStop: the FragmentManager state is now saved.
            scenario.moveToState(Lifecycle.State.CREATED)

            lateinit var host: StaleHostActivity
            scenario.onActivity { host = it }
            BiometricHelper.setForegroundActivityForTest(host)

            var failure: Throwable? = null
            val completed = runBlocking {
                withTimeoutOrNull(5_000) {
                    runCatching {
                        BiometricHelper.authenticate(
                            subtitle = "test",
                            allowDeviceCredentialFallback = true,
                        )
                    }.onFailure { failure = it }
                }
            }

            assertNotNull(completed, "authenticate() hung on a stopped host instead of failing fast")
            assertTrue(
                failure is BiometricAuthException,
                "expected BiometricAuthException, was: $failure",
            )
        } finally {
            BiometricHelper.setForegroundActivityForTest(null)
            scenario.close()
        }
    }
}
