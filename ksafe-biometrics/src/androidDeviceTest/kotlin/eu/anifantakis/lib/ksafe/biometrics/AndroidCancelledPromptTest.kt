package eu.anifantakis.lib.ksafe.biometrics

import android.os.Handler
import android.os.Looper
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Host for the queued-prompt case; stays RESUMED and never shows UI. */
class PromptHostActivity : FragmentActivity()

/**
 * Locks in: a `verifyBiometric` cancelled while its show is still queued on a busy main looper
 * never reaches `BiometricPrompt.authenticate`, so the system sheet cannot appear over the
 * screen the user moved on to.
 *
 * The show seam stands in for the sheet — it counts the attempt and throws, so the assertions
 * are exact and no real prompt is ever raised. Needs no enrolled biometric.
 */
@RunWith(AndroidJUnit4::class)
class AndroidCancelledPromptTest {

    private val main = Handler(Looper.getMainLooper())
    private val shows = AtomicInteger(0)

    @Test
    fun cancellationWhileTheShowIsQueued_neverReachesTheSystemSheet() {
        val scenario = ActivityScenario.launch(PromptHostActivity::class.java)
        try {
            scenario.moveToState(Lifecycle.State.RESUMED)
            lateinit var host: PromptHostActivity
            scenario.onActivity { host = it }
            BiometricHelper.setForegroundActivityForTest(host)
            BiometricHelper.beforePromptShowForTest = {
                shows.incrementAndGet()
                throw IllegalStateException("the test seam stands in for the system sheet")
            }

            // Control: an uncancelled caller DOES reach the show once the looper drains, which
            // is what makes the assertion below meaningful rather than vacuous.
            val uncancelled = promptBehindABusyLooper(cancelWhileQueued = false)
            assertEquals(1, shows.get(), "the queued show must run once the main looper drains")
            assertTrue(
                uncancelled is BiometricAuthException,
                "the seam's failure must surface as BiometricAuthException, was: $uncancelled",
            )

            val cancelled = promptBehindABusyLooper(cancelWhileQueued = true)
            assertEquals(1, shows.get(), "a cancelled request must never reach BiometricPrompt.authenticate")
            assertTrue(
                cancelled is CancellationException,
                "the cancelled caller must complete with CancellationException, was: $cancelled",
            )
        } finally {
            BiometricHelper.beforePromptShowForTest = null
            BiometricHelper.setForegroundActivityForTest(null)
            scenario.close()
        }
    }

    /**
     * Blocks the main looper, starts an `authenticate()` so its show posts behind the blocker,
     * optionally cancels it while it sits there, then releases and drains. Returns what the
     * caller completed with.
     */
    private fun promptBehindABusyLooper(cancelWhileQueued: Boolean): Throwable? {
        val release = CountDownLatch(1)
        val blocked = CountDownLatch(1)
        main.post {
            blocked.countDown()
            release.await()
        }
        assertTrue(blocked.await(5, TimeUnit.SECONDS), "the main looper never picked up the blocker")

        var outcome: Throwable? = null
        val job = CoroutineScope(Dispatchers.IO).launch {
            try {
                BiometricHelper.authenticate(subtitle = "test", allowDeviceCredentialFallback = true)
            } catch (t: Throwable) {
                outcome = t
            }
        }
        // The caller resolves the host from the test seam and posts immediately; it has nothing
        // else to wait on, so this is ample for the show to be sitting behind the blocker.
        Thread.sleep(500)

        if (cancelWhileQueued) {
            job.cancel()
            job.awaitCompletion()
        }
        release.countDown()
        drainMain()
        job.awaitCompletion()
        return outcome
    }

    private fun Job.awaitCompletion() {
        runBlocking { assertTrue(withTimeoutOrNull(5_000) { join(); true } == true, "the caller never completed") }
    }

    private fun drainMain() {
        val drained = CountDownLatch(1)
        main.post { drained.countDown() }
        assertTrue(drained.await(5, TimeUnit.SECONDS), "the main looper did not drain")
    }
}
