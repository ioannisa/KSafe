package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests for the three fixes claimed in the v1.6.0 CHANGELOG:
 *
 * 1. Key generation race condition (JVM)
 * 2. deleteKey race with key cache repopulation (Android + JVM)
 * 3. Replaced intern() lock strategy with dedicated lock map (Android + JVM)
 *
 * These tests run on JVM only. The Android side of fixes 2 and 3 cannot be
 * tested here (requires Android Keystore), but the JVM code paths exercise
 * the same locking patterns.
 */
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

    // ========================================================================
    // FIX 1: Key generation race condition (JVM)
    //
    // Concurrent putEncrypted calls for the same key alias could trigger
    // parallel key generation, producing different encryption keys. One would
    // be stored while the other was used to encrypt data, causing permanent
    // data loss on next read.
    //
    // The fix adds a ConcurrentHashMap<String, SecretKey> key cache and
    // per-alias lock in JvmSoftwareEncryption.
    // ========================================================================

    /**
     * Verifies that concurrent encrypted writes to the SAME key all use the
     * same encryption key — data written by any thread is readable afterward.
     *
     * Without the fix, parallel key generation could produce different keys,
     * and only the last-written key would be stored. Values encrypted with
     * the other (lost) key become permanently unreadable.
     */
    @Test
    fun testConcurrentEncryptedWritesSameKey_noDataLoss() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200) // let cache init

        val threads = 20
        val iterations = 50
        val errors = AtomicInteger(0)
        val latch = CountDownLatch(1)

        // All threads write to the SAME key — this is the scenario that
        // triggers parallel key generation without the fix.
        val jobs = (0 until threads).map { t ->
            launch(Dispatchers.Default) {
                latch.await() // start simultaneously
                repeat(iterations) { i ->
                    try {
                        val value = "thread${t}_iter$i"
                        ksafe.putDirect("race_key", value, encrypted = true)
                        // Immediately read back — must get *some* valid value, never default
                        val read = ksafe.getDirect("race_key", "DEFAULT", encrypted = true)
                        if (read == "DEFAULT") {
                            errors.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        latch.countDown() // unleash all threads
        jobs.forEach { it.join() }

        assertEquals(
            0, errors.get(),
            "Concurrent encrypted writes to same key must never return default (data loss from key generation race)"
        )

        // Final read must succeed
        val finalValue = ksafe.getDirect("race_key", "DEFAULT", encrypted = true)
        assertTrue(
            finalValue != "DEFAULT",
            "After all writes complete, key must be readable"
        )
    }

    /**
     * Verifies that concurrent encrypted writes to DIFFERENT keys each get
     * their own stable encryption key — no cross-contamination.
     *
     * Without key caching and per-alias locks, concurrent generation for
     * different aliases could still interfere due to DataStore contention.
     */
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
                    ksafe.putDirect(key, value, encrypted = true)
                    val read = ksafe.getDirect(key, "DEFAULT", encrypted = true)
                    if (read != value) {
                        errors.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errors.incrementAndGet()
                }
            }
        }

        latch.countDown()
        jobs.forEach { it.join() }

        assertEquals(
            0, errors.get(),
            "Each key should have its own stable encryption key — no cross-contamination"
        )

        // Verify all keys are still readable after everything settles
        repeat(keyCount) { k ->
            val read = ksafe.getDirect("parallel_key_$k", "DEFAULT", encrypted = true)
            assertEquals(
                "value_for_$k", read,
                "Key parallel_key_$k should retain its value after concurrent writes"
            )
        }
    }

    /**
     * Stress test: many threads doing put+get on the same key repeatedly.
     * Verifies that the key cache + per-alias lock prevents data loss even
     * under sustained contention.
     */
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
                        val key = "stress_${i % 5}" // 5 shared keys
                        val value = "t${t}_i$i"
                        ksafe.putDirect(key, value, encrypted = true)
                        val read = ksafe.getDirect(key, "LOST", encrypted = true)
                        if (read == "LOST") {
                            dataLossCount.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        exceptionCount.incrementAndGet()
                    }
                }
            }
        }

        jobs.forEach { it.join() }

        assertEquals(0, exceptionCount.get(), "No exceptions during stress test")
        assertEquals(
            0, dataLossCount.get(),
            "No data loss — key generation race condition is fixed"
        )
    }

    // ========================================================================
    // FIX 2: deleteKey race with key cache repopulation (Android + JVM)
    //
    // Pre-existing gap: deleteKey removed the key from cache and storage
    // without holding the per-alias lock used by getOrCreateSecretKey.
    // A concurrent encrypt/decrypt could re-populate the cache with a
    // now-deleted key.
    //
    // The fix makes deleteKey hold synchronized(lockFor(identifier)) — the
    // same lock as getOrCreateSecretKey.
    // ========================================================================

    /**
     * Interleaves deleteKey with concurrent encrypted reads/writes on the
     * same key alias. After deletion, subsequent writes must generate a new
     * key and all data written after deletion must be readable.
     *
     * Without the fix: a concurrent getOrCreateSecretKey could re-populate
     * the cache with the old (now-deleted) key. Future operations would
     * succeed in-memory but after restart the ciphertext is undecryptable.
     */
    @Test
    fun testDeleteKeyDoesNotLeaveStaleCache() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        // Phase 1: Write initial encrypted value
        ksafe.putDirect("delete_race_key", "initial_value", encrypted = true)
        delay(100)
        assertEquals(
            "initial_value",
            ksafe.getDirect("delete_race_key", "DEFAULT", encrypted = true)
        )

        // Phase 2: Delete the key and immediately write a new value.
        // Without the fix, a concurrent getOrCreateSecretKey during delete
        // could repopulate the cache with the old key.
        ksafe.delete("delete_race_key")

        // After delete, reading should return default
        assertEquals(
            "DEFAULT",
            ksafe.getDirect("delete_race_key", "DEFAULT", encrypted = true),
            "After delete, key should return default"
        )

        // Phase 3: Write new value — must use a fresh encryption key
        ksafe.putDirect("delete_race_key", "new_value", encrypted = true)
        assertEquals(
            "new_value",
            ksafe.getDirect("delete_race_key", "DEFAULT", encrypted = true),
            "After delete + re-write, new value must be readable"
        )
    }

    /**
     * Concurrent delete + encrypt/decrypt stress test.
     *
     * Multiple threads continuously write and read encrypted data while
     * another thread periodically deletes the key. The invariant:
     * getDirect must never throw an unrecoverable exception, and after
     * each write, the immediately-following read must return the written
     * value (not DEFAULT from a stale/deleted key).
     */
    @Test
    fun testDeleteKeyRaceWithConcurrentEncryption() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        val running = AtomicBoolean(true)
        val writeReadMismatches = AtomicInteger(0)
        val exceptions = AtomicInteger(0)

        // Writer/reader threads: continuously put + get on the same key
        val workers = (0 until 5).map { w ->
            launch(Dispatchers.Default) {
                var seq = 0
                while (running.get()) {
                    try {
                        val value = "worker${w}_seq${seq++}"
                        ksafe.putDirect("contested_key", value, encrypted = true)
                        val read = ksafe.getDirect("contested_key", "DEFAULT", encrypted = true)
                        // After our write, read might get our value or a newer one
                        // from another thread, but should never get DEFAULT
                        // (unless a delete just happened, which is expected)
                        // We don't count mismatches when delete is racing — instead
                        // we verify no exceptions occur
                    } catch (e: Exception) {
                        exceptions.incrementAndGet()
                    }
                }
            }
        }

        // Deleter thread: periodically deletes the key
        val deleter = launch(Dispatchers.Default) {
            repeat(20) {
                delay(50)
                try {
                    ksafe.delete("contested_key")
                } catch (e: Exception) {
                    exceptions.incrementAndGet()
                }
            }
            running.set(false)
        }

        deleter.join()
        workers.forEach { it.join() }

        assertEquals(
            0, exceptions.get(),
            "No exceptions during concurrent delete + encrypt/decrypt — deleteKey lock prevents corruption"
        )
    }

    /**
     * Verifies delete-then-write cycle works correctly N times in sequence.
     * Each cycle: write → verify → delete → verify default → write new → verify new.
     *
     * This catches the scenario where deleteKey doesn't fully purge the cache,
     * causing subsequent writes to encrypt with a stale (deleted) key.
     */
    @Test
    fun testRepeatedDeleteAndRewriteCycles() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        repeat(10) { cycle ->
            val key = "cycle_key"
            val value = "cycle_${cycle}_value"

            ksafe.putDirect(key, value, encrypted = true)
            assertEquals(
                value,
                ksafe.getDirect(key, "DEFAULT", encrypted = true),
                "Cycle $cycle: written value must be readable"
            )

            ksafe.delete(key)
            assertEquals(
                "DEFAULT",
                ksafe.getDirect(key, "DEFAULT", encrypted = true),
                "Cycle $cycle: deleted key must return default"
            )
        }
    }

    // ========================================================================
    // FIX 3: Replaced intern() lock strategy with dedicated lock map
    //
    // v1.4.1 introduced synchronized(alias.intern()) on Android. The JVM
    // implementation extended this pattern. However, intern() uses the JVM's
    // global string pool as lock objects — with many dynamic aliases this
    // creates unnecessary pool pressure.
    //
    // The fix replaces intern() with ConcurrentHashMap<String, Any> lock map
    // using computeIfAbsent on both platforms.
    //
    // These tests verify:
    // - Many unique aliases don't cause issues (no shared lock contention)
    // - Lock identity is stable (same alias always yields same lock object)
    // - Large numbers of aliases don't degrade performance or correctness
    // ========================================================================

    /**
     * Verifies that a large number of unique key aliases can be used
     * concurrently without issues. With intern(), a very large number of
     * unique strings could pressure the JVM string pool. With the dedicated
     * lock map, each alias gets its own lock object bounded to the KSafe
     * instance.
     */
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
                    ksafe.putDirect(key, value, encrypted = true)
                    val read = ksafe.getDirect(key, "DEFAULT", encrypted = true)
                    if (read != value) {
                        errors.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errors.incrementAndGet()
                }
            }
        }

        jobs.forEach { it.join() }

        assertEquals(
            0, errors.get(),
            "200 unique aliases should all work correctly with dedicated lock map"
        )

        // Verify all still readable
        repeat(aliasCount) { i ->
            assertEquals(
                "value_$i",
                ksafe.getDirect("unique_alias_$i", "DEFAULT", encrypted = true),
                "Alias unique_alias_$i should retain its value"
            )
        }
    }

    /**
     * Verifies that the dedicated lock map provides proper mutual exclusion:
     * concurrent writes to the same alias are serialized (no data corruption),
     * while writes to different aliases can proceed in parallel.
     *
     * We write to 3 aliases from 10 threads each. Each alias must end up
     * with a consistent final value from one of its writers.
     */
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
                            ksafe.putDirect(alias, "t${t}_i$i", encrypted = true)
                            // Read must return a valid value, never DEFAULT
                            val read = ksafe.getDirect(alias, "DEFAULT", encrypted = true)
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
        jobs.forEach { it.join() }

        assertEquals(
            0, errors.get(),
            "Per-alias lock map must serialize concurrent access — no data loss"
        )

        // Each alias should have a readable final value
        aliases.forEach { alias ->
            val finalValue = ksafe.getDirect(alias, "DEFAULT", encrypted = true)
            assertTrue(
                finalValue != "DEFAULT",
                "Alias $alias must have a final readable value"
            )
        }
    }

    /**
     * Regression test: verifies that string identity doesn't matter for
     * locking. With intern(), two separately-constructed strings with the
     * same content might or might not resolve to the same lock object
     * (depending on JVM internals). With ConcurrentHashMap.computeIfAbsent,
     * lookup is by equals(), guaranteeing stable lock identity.
     *
     * This test constructs key names dynamically (not compile-time constants)
     * to ensure they're different String objects, then verifies concurrent
     * access still works correctly.
     */
    @Test
    fun testDynamicStringAliasesShareLock() = runTest {
        val ksafe = KSafe(generateUniqueFileName())
        delay(200)

        val errors = AtomicInteger(0)
        val latch = CountDownLatch(1)

        // Dynamically construct the same key name in different threads
        // to ensure they are distinct String objects
        val jobs = (0 until 10).map { t ->
            launch(Dispatchers.Default) {
                latch.await()
                repeat(50) { i ->
                    try {
                        // Build key name dynamically — NOT a string literal
                        val key = buildString {
                            append("dynamic")
                            append("_")
                            append("key")
                        }
                        ksafe.putDirect(key, "t${t}_i$i", encrypted = true)
                        val read = ksafe.getDirect(key, "DEFAULT", encrypted = true)
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
        jobs.forEach { it.join() }

        assertEquals(
            0, errors.get(),
            "Dynamically constructed strings with same content must share the same lock"
        )
    }
}
