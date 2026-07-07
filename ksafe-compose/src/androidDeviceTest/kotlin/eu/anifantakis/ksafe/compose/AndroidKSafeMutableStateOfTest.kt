package eu.anifantakis.ksafe.compose

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.KSafe
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test

/**
 * Android instrumented [KSafeMutableStateOfTest] impl (real device/emulator). DataStore forbids
 * multiple instances on one file, so each test uses a unique fileName.
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

    /** Skipped on Android: DataStore doesn't allow multiple instances on the same file in one process. */
    @Test
    override fun mutableStateOf_persistsAcrossInstances() {
        println("Skipped: mutableStateOf_persistsAcrossInstances (Android DataStore limitation)")
    }

    override fun newKSafe(fileName: String?): KSafe {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val uniqueName = if (fileName != null) {
            "composeandroid${runId}${fileName}"
        } else {
            generateUniqueFileName()
        }
        return KSafe(context, uniqueName)
    }
}
