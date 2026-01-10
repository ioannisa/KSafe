package eu.anifantakis.ksafe.compose

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.KSafe
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test

/**
 * Android-specific instrumented test implementation for KSafe.mutableStateOf tests.
 * Runs on an actual Android device or emulator with real EncryptedSharedPreferences.
 *
 * IMPORTANT: DataStore doesn't allow multiple instances to access the same file.
 * Each test must use a unique file name to avoid IllegalStateException.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKSafeMutableStateOfTest : KSafeMutableStateOfTest() {

    companion object {
        private val testCounter = AtomicInteger(0)
        private val runId: String = numberToLetters(System.currentTimeMillis())

        private fun generateUniqueFileName(): String {
            val count = testCounter.incrementAndGet()
            return "composeandroid${runId}test${numberToLetters(count.toLong())}"
        }

        private fun numberToLetters(num: Long): String {
            var n = num
            val sb = StringBuilder()
            while (n > 0) {
                n--
                sb.insert(0, ('a' + (n % 26).toInt()))
                n /= 26
            }
            return if (sb.isEmpty()) "a" else sb.toString()
        }
    }

    /**
     * Skip this test on Android - DataStore doesn't support multiple instances
     * accessing the same file simultaneously within the same process.
     */
    @Test
    override fun mutableStateOf_persistsAcrossInstances() {
        // Skipped on Android due to DataStore limitation (same as JVM)
        println("Skipped: mutableStateOf_persistsAcrossInstances (Android DataStore limitation)")
    }

    override fun createKSafe(fileName: String?): KSafe {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val uniqueName = if (fileName != null) {
            "composeandroid${runId}${fileName}"
        } else {
            generateUniqueFileName()
        }
        return KSafe(context, uniqueName)
    }
}
