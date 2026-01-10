package eu.anifantakis.ksafe.compose

import eu.anifantakis.lib.ksafe.KSafe
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test

/**
 * JVM-specific test implementation for KSafe.mutableStateOf tests.
 *
 * IMPORTANT: DataStore on JVM does not allow multiple instances to access the same file.
 * Each test must use a unique file name to avoid IllegalArgumentException.
 */
class JvmKSafeMutableStateOfTest : KSafeMutableStateOfTest() {

    /**
     * Skip this test on JVM - DataStore doesn't support multiple instances
     * accessing the same file simultaneously.
     */
    @Test
    override fun mutableStateOf_persistsAcrossInstances() {
        // Skipped on JVM due to DataStore limitation
        println("Skipped: mutableStateOf_persistsAcrossInstances (JVM DataStore limitation)")
    }

    companion object {
        // Atomic counter to ensure unique file names across all tests in a single run
        private val testCounter = AtomicInteger(0)

        // Timestamp prefix ensures uniqueness across test runs
        private val runId: String = numberToLetters(System.currentTimeMillis())

        /**
         * Generates a unique file name using only lowercase letters.
         */
        private fun generateUniqueFileName(): String {
            val count = testCounter.incrementAndGet()
            return "composerun${runId}test${numberToLetters(count.toLong())}"
        }

        /**
         * Converts a number to base-26 using letters a-z.
         */
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

    override fun createKSafe(fileName: String?): KSafe {
        val uniqueName = if (fileName != null) {
            "composerun${runId}${fileName}"
        } else {
            generateUniqueFileName()
        }
        return KSafe(uniqueName)
    }
}
