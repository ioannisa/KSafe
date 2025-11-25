package eu.anifantakis.lib.ksafe

import java.util.concurrent.atomic.AtomicInteger

/**
 * JVM-specific test implementation.
 *
 * IMPORTANT: DataStore on JVM does not allow multiple instances to access the same file.
 * Each test must use a unique file name to avoid IllegalArgumentException.
 *
 * We also need unique names ACROSS test runs because files persist on disk.
 */
class JvmKSafeTest : KSafeTest() {

    companion object {
        // Atomic counter to ensure unique file names across all tests in a single run
        private val testCounter = AtomicInteger(0)

        // Timestamp prefix ensures uniqueness across test runs
        // Convert to base-26 letters since KSafe only allows [a-z]+
        private val runId: String = numberToLetters(System.currentTimeMillis())

        /**
         * Generates a unique file name using only lowercase letters.
         * KSafe requires file names to match regex [a-z]+
         *
         * Format: run{timestamp}test{counter}
         * This ensures uniqueness both within a test run and across multiple runs.
         */
        private fun generateUniqueFileName(): String {
            val count = testCounter.incrementAndGet()
            return "run${runId}test${numberToLetters(count.toLong())}"
        }

        /**
         * Converts a number to base-26 using letters a-z.
         * Example: 1 -> "a", 26 -> "z", 27 -> "aa", etc.
         */
        private fun numberToLetters(num: Long): String {
            var n = num
            val sb = StringBuilder()
            while (n > 0) {
                n-- // Adjust for 0-based indexing (a=0, not a=1)
                sb.insert(0, ('a' + (n % 26).toInt()))
                n /= 26
            }
            return if (sb.isEmpty()) "a" else sb.toString()
        }
    }

    override fun createKSafe(fileName: String?): KSafe {
        // If a specific fileName is requested (for isolation tests), make it unique too
        val uniqueName = if (fileName != null) {
            "run${runId}${fileName}"
        } else {
            generateUniqueFileName()
        }
        return KSafe(uniqueName)
    }
}