package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals

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

    // ============ CONCURRENCY STRESS TESTS ============
    // These tests specifically target race conditions that can occur under heavy load

    /**
     * Stress test for concurrent putDirect operations.
     * This simulates the benchmark scenario where rapid-fire writes
     * can cause race conditions with the background cache updater.
     *
     * The bug this catches: NoSuchElementException when iterating
     * ConcurrentHashMap while another thread modifies it.
     */
    @Test
    fun testConcurrentPutDirectStress() = runTest {
        val ksafe = createKSafe()
        val iterations = 500
        val concurrentWriters = 10
        val errors = AtomicInteger(0)
        val successfulWrites = AtomicInteger(0)

        // Launch multiple coroutines doing rapid putDirect operations
        val jobs = (0 until concurrentWriters).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        ksafe.putDirect("writer${writerId}_key$i", "value_$i", encrypted = false)
                        successfulWrites.incrementAndGet()
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                        println("Error in writer $writerId iteration $i: ${e.message}")
                    }
                }
            }
        }

        // Wait for all writers to complete
        jobs.forEach { it.join() }

        // No delay needed - errors are caught during putDirect() execution
        // Background persistence happens async but doesn't affect test correctness

        assertEquals(0, errors.get(), "Should have no errors during concurrent writes")
        assertEquals(
            concurrentWriters * iterations,
            successfulWrites.get(),
            "All writes should succeed"
        )
    }

    /**
     * Stress test for concurrent encrypted putDirect operations.
     * Encrypted writes involve more operations (encryption, key lookup)
     * and are more likely to trigger race conditions.
     */
    @Test
    fun testConcurrentEncryptedPutDirectStress() = runTest {
        val ksafe = createKSafe()
        val iterations = 100
        val concurrentWriters = 5
        val errors = AtomicInteger(0)
        val successfulWrites = AtomicInteger(0)

        val jobs = (0 until concurrentWriters).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        ksafe.putDirect("enc_writer${writerId}_key$i", "encrypted_value_$i", encrypted = true)
                        successfulWrites.incrementAndGet()
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                        println("Error in encrypted writer $writerId iteration $i: ${e.message}")
                    }
                }
            }
        }

        jobs.forEach { it.join() }

        assertEquals(0, errors.get(), "Should have no errors during concurrent encrypted writes")
    }

    /**
     * Stress test for mixed read/write operations.
     * This tests the scenario where reads and writes happen simultaneously
     * on the same keys.
     */
    @Test
    fun testConcurrentReadWriteStress() = runTest {
        val ksafe = createKSafe()
        val iterations = 200
        val errors = AtomicInteger(0)
        val running = AtomicBoolean(true)

        // Pre-populate some data
        repeat(50) { i ->
            ksafe.putDirect("shared_key_$i", "initial_$i", encrypted = false)
        }

        // Writer coroutine
        val writer = launch(Dispatchers.Default) {
            repeat(iterations) { i ->
                try {
                    ksafe.putDirect("shared_key_${i % 50}", "updated_$i", encrypted = false)
                } catch (e: Exception) {
                    errors.incrementAndGet()
                    println("Writer error at $i: ${e.message}")
                }
            }
            running.set(false)
        }

        // Reader coroutines
        val readers = (0 until 5).map { readerId ->
            launch(Dispatchers.Default) {
                while (running.get()) {
                    try {
                        repeat(50) { i ->
                            ksafe.getDirect("shared_key_$i", "default", encrypted = false)
                        }
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                        println("Reader $readerId error: ${e.message}")
                    }
                }
            }
        }

        writer.join()
        readers.forEach { it.join() }

        assertEquals(0, errors.get(), "Should have no errors during concurrent read/write")
    }

    /**
     * Stress test specifically for the dirty keys mechanism.
     * This rapidly adds and removes dirty keys to stress the
     * ConcurrentHashMap iteration that was causing NoSuchElementException.
     */
    @Test
    fun testDirtyKeysStress() = runTest {
        val ksafe = createKSafe()
        val iterations = 1000
        val errors = AtomicInteger(0)

        // Rapid fire writes that add dirty keys
        val jobs = (0 until 20).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        // This adds to dirty keys, updates cache
                        ksafe.putDirect("dirty_test_${writerId}_$i", "v$i", encrypted = false)
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                        if (errors.get() <= 5) {
                            println("Dirty keys stress error: ${e::class.simpleName}: ${e.message}")
                        }
                    }
                }
            }
        }

        jobs.forEach { it.join() }

        assertTrue(
            errors.get() == 0,
            "Dirty keys stress test should complete without NoSuchElementException. Errors: ${errors.get()}"
        )
    }

}