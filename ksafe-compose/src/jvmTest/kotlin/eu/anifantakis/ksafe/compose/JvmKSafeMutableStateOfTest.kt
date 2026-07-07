package eu.anifantakis.ksafe.compose

import eu.anifantakis.lib.ksafe.KSafe
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test

/**
 * JVM [KSafeMutableStateOfTest] impl. DataStore forbids multiple instances on one file,
 * so each test uses a unique fileName.
 */
class JvmKSafeMutableStateOfTest : KSafeMutableStateOfTest() {

    /** Skipped on JVM: DataStore doesn't allow multiple instances on the same file. */
    @Test
    override fun mutableStateOf_persistsAcrossInstances() {
        println("Skipped: mutableStateOf_persistsAcrossInstances (JVM DataStore limitation)")
    }

    companion object {
        private val testCounter = AtomicInteger(0)
        private val runId: String = numberToLetters(System.currentTimeMillis())

        private fun generateUniqueFileName(): String {
            val count = testCounter.incrementAndGet()
            return "composerun${runId}test${numberToLetters(count.toLong())}"
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

    override fun newKSafe(fileName: String?): KSafe {
        val uniqueName = if (fileName != null) {
            "composerun${runId}${fileName}"
        } else {
            generateUniqueFileName()
        }
        return KSafe(uniqueName)
    }
}
