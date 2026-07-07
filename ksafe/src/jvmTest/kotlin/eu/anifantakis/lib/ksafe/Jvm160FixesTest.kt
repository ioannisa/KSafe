package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Locks in: the engine's per-alias key handling — one key per alias under concurrent generation, deleteKey/cache synchronization, and dedicated-lock-map mutual exclusion. */
class Jvm160FixesTest {

    companion object {
        private val testCounter = AtomicInteger(0)
        private val runId: String = numberToLetters(System.currentTimeMillis())

        fun generateUniqueFileName(): String {
            val count = testCounter.incrementAndGet()
            return "run${runId}fix${numberToLetters(count.toLong())}"
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

    /** Concurrent encrypted writes to the SAME key must all use one key, so any thread's data stays readable. */
    @Test
    fun testConcurrentEncryptedWritesSameKey_noDataLoss() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        val threads = 20
        val iterations = 50
        val errors = AtomicInteger(0)
        val latch = CountDownLatch(1)

        val jobs = (0 until threads).map { t ->
            launch(Dispatchers.Default) {
                latch.await()
                repeat(iterations) { i ->
                    try {
                        val value = "thread${t}_iter$i"
                        ksafe.putDirect("race_key", value)
                        val read = ksafe.getDirect("race_key", "DEFAULT")
                        if (read == "DEFAULT") {
                            errors.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        latch.countDown()
        jobs.joinAll()

        assertEquals(
            0, errors.get(),
            "Concurrent encrypted writes to same key must never return default (data loss from key generation race)"
        )

        val finalValue = ksafe.getDirect("race_key", "DEFAULT")
        assertTrue(
            finalValue != "DEFAULT",
            "After all writes complete, key must be readable"
        )
    }

    /** Concurrent encrypted writes to DIFFERENT keys each get their own stable key — no cross-contamination. */
    @Test
    fun testConcurrentEncryptedWritesDifferentKeys_allReadable() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        val keyCount = 30
        val errors = AtomicInteger(0)
        val latch = CountDownLatch(1)

        val jobs = (0 until keyCount).map { k ->
            launch(Dispatchers.Default) {
                latch.await()
                try {
                    val key = "parallel_key_$k"
                    val value = "value_for_$k"
                    ksafe.putDirect(key, value)
                    val read = ksafe.getDirect(key, "DEFAULT")
                    if (read != value) {
                        errors.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errors.incrementAndGet()
                }
            }
        }

        latch.countDown()
        jobs.joinAll()

        assertEquals(
            0, errors.get(),
            "Each key should have its own stable encryption key — no cross-contamination"
        )

        repeat(keyCount) { k ->
            val read = ksafe.getDirect("parallel_key_$k", "DEFAULT")
            assertEquals(
                "value_for_$k", read,
                "Key parallel_key_$k should retain its value after concurrent writes"
            )
        }
    }

    /** Stress: many threads put+get the same key — the key cache + per-alias lock must prevent data loss under sustained contention. */
    @Test
    fun testKeyGenerationRaceStress() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        val threads = 10
        val iterations = 100
        val dataLossCount = AtomicInteger(0)
        val exceptionCount = AtomicInteger(0)

        val jobs = (0 until threads).map { t ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        val key = "stress_${i % 5}"
                        val value = "t${t}_i$i"
                        ksafe.putDirect(key, value)
                        val read = ksafe.getDirect(key, "LOST")
                        if (read == "LOST") {
                            dataLossCount.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        exceptionCount.incrementAndGet()
                    }
                }
            }
        }

        jobs.joinAll()

        assertEquals(0, exceptionCount.get(), "No exceptions during stress test")
        assertEquals(
            0, dataLossCount.get(),
            "No data loss — key generation race condition is fixed"
        )
    }

    /** After deleteKey, a re-write must mint a new key and stay readable; a stale cached key would leave ciphertext undecryptable after restart. */
    @Test
    fun testDeleteKeyDoesNotLeaveStaleCache() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        ksafe.putDirect("delete_race_key", "initial_value")
        delay(100)
        assertEquals(
            "initial_value",
            ksafe.getDirect("delete_race_key", "DEFAULT")
        )

        // A concurrent getOrCreateSecretKey during delete must not repopulate the cache with the old key.
        ksafe.delete("delete_race_key")

        assertEquals(
            "DEFAULT",
            ksafe.getDirect("delete_race_key", "DEFAULT"),
            "After delete, key should return default"
        )

        ksafe.putDirect("delete_race_key", "new_value")
        assertEquals(
            "new_value",
            ksafe.getDirect("delete_race_key", "DEFAULT"),
            "After delete + re-write, new value must be readable"
        )
    }

    /** Concurrent delete + encrypt/decrypt: getDirect must never throw, even while another thread periodically deletes the key. */
    @Test
    fun testDeleteKeyRaceWithConcurrentEncryption() = runTest(timeout = 90.seconds) {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        val writeReadMismatches = AtomicInteger(0)
        val exceptions = AtomicInteger(0)

        // putDirect/getDirect don't suspend, so each arm yield()s — without it 5 workers pin the
        // pool and starve the delay()-suspended deleter (deadlock).
        val workerIterations = 200
        val workers = (0 until 5).map { w ->
            launch(Dispatchers.Default) {
                repeat(workerIterations) { i ->
                    try {
                        val value = "worker${w}_seq$i"
                        ksafe.putDirect("contested_key", value)
                        val read = ksafe.getDirect("contested_key", "DEFAULT")
                        // May see our value, a newer one, or default while a delete races — it must just not throw.
                    } catch (e: Exception) {
                        exceptions.incrementAndGet()
                    }
                    yield()
                }
            }
        }

        val deleter = launch(Dispatchers.Default) {
            repeat(20) {
                delay(50)
                try {
                    ksafe.delete("contested_key")
                } catch (e: Exception) {
                    exceptions.incrementAndGet()
                }
            }
        }

        deleter.join()
        workers.joinAll()

        assertEquals(
            0, exceptions.get(),
            "No exceptions during concurrent delete + encrypt/decrypt — deleteKey lock prevents corruption"
        )
    }

    /** Repeated delete-then-rewrite cycles must stay correct — catches deleteKey not fully purging the cache. */
    @Test
    fun testRepeatedDeleteAndRewriteCycles() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        repeat(10) { cycle ->
            val key = "cycle_key"
            val value = "cycle_${cycle}_value"

            ksafe.putDirect(key, value)
            assertEquals(
                value,
                ksafe.getDirect(key, "DEFAULT"),
                "Cycle $cycle: written value must be readable"
            )

            ksafe.delete(key)
            assertEquals(
                "DEFAULT",
                ksafe.getDirect(key, "DEFAULT"),
                "Cycle $cycle: deleted key must return default"
            )
        }
    }

    /** Many unique aliases work concurrently: the dedicated lock map bounds each alias's lock to the instance, unlike intern()'s global string pool. */
    @Test
    fun testManyUniqueAliasesWork() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        val aliasCount = 200
        val errors = AtomicInteger(0)

        val jobs = (0 until aliasCount).map { i ->
            launch(Dispatchers.Default) {
                try {
                    val key = "unique_alias_$i"
                    val value = "value_$i"
                    ksafe.putDirect(key, value)
                    val read = ksafe.getDirect(key, "DEFAULT")
                    if (read != value) {
                        errors.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errors.incrementAndGet()
                }
            }
        }

        jobs.joinAll()

        assertEquals(
            0, errors.get(),
            "200 unique aliases should all work correctly with dedicated lock map"
        )

        repeat(aliasCount) { i ->
            assertEquals(
                "value_$i",
                ksafe.getDirect("unique_alias_$i", "DEFAULT"),
                "Alias unique_alias_$i should retain its value"
            )
        }
    }

    /** The lock map serializes concurrent writes per alias (no corruption) while different aliases proceed in parallel. */
    @Test
    fun testLockMapSerializesPerAlias() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        val aliases = listOf("alias_a", "alias_b", "alias_c")
        val threadsPerAlias = 10
        val iterationsPerThread = 50
        val errors = AtomicInteger(0)
        val latch = CountDownLatch(1)

        val jobs = aliases.flatMap { alias ->
            (0 until threadsPerAlias).map { t ->
                launch(Dispatchers.Default) {
                    latch.await()
                    repeat(iterationsPerThread) { i ->
                        try {
                            ksafe.putDirect(alias, "t${t}_i$i")
                            val read = ksafe.getDirect(alias, "DEFAULT")
                            if (read == "DEFAULT") {
                                errors.incrementAndGet()
                            }
                        } catch (e: Exception) {
                            errors.incrementAndGet()
                        }
                    }
                }
            }
        }

        latch.countDown()
        jobs.joinAll()

        assertEquals(
            0, errors.get(),
            "Per-alias lock map must serialize concurrent access — no data loss"
        )

        aliases.forEach { alias ->
            val finalValue = ksafe.getDirect(alias, "DEFAULT")
            assertTrue(
                finalValue != "DEFAULT",
                "Alias $alias must have a final readable value"
            )
        }
    }

    /** Lock lookup is by equals(), not identity: dynamically-built strings with the same content must share one lock object. */
    @Test
    fun testDynamicStringAliasesShareLock() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        val errors = AtomicInteger(0)
        val latch = CountDownLatch(1)

        val jobs = (0 until 10).map { t ->
            launch(Dispatchers.Default) {
                latch.await()
                repeat(50) { i ->
                    try {
                        val key = buildString {
                            append("dynamic")
                            append("_")
                            append("key")
                        }
                        ksafe.putDirect(key, "t${t}_i$i")
                        val read = ksafe.getDirect(key, "DEFAULT")
                        if (read == "DEFAULT") {
                            errors.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        latch.countDown()
        jobs.joinAll()

        assertEquals(
            0, errors.get(),
            "Dynamically constructed strings with same content must share the same lock"
        )
    }
}
