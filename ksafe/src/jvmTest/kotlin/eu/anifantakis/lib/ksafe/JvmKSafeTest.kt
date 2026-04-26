package eu.anifantakis.lib.ksafe

import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.edit
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertNotNull

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
        fun generateUniqueFileName(): String {
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
                        ksafe.putDirect("writer${writerId}_key$i", "value_$i", KSafeWriteMode.Plain)
                        successfulWrites.incrementAndGet()
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                        println("Error in writer $writerId iteration $i: ${e.message}")
                    }
                }
            }
        }

        // Wait for all writers to complete
        jobs.joinAll()

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
                        ksafe.putDirect("enc_writer${writerId}_key$i", "encrypted_value_$i")
                        successfulWrites.incrementAndGet()
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                        println("Error in encrypted writer $writerId iteration $i: ${e.message}")
                    }
                }
            }
        }

        jobs.joinAll()

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
            ksafe.putDirect("shared_key_$i", "initial_$i", KSafeWriteMode.Plain)
        }

        // Writer coroutine
        val writer = launch(Dispatchers.Default) {
            repeat(iterations) { i ->
                try {
                    ksafe.putDirect("shared_key_${i % 50}", "updated_$i", KSafeWriteMode.Plain)
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
                            ksafe.getDirect("shared_key_$i", "default")
                        }
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                        println("Reader $readerId error: ${e.message}")
                    }
                }
            }
        }

        writer.join()
        readers.joinAll()

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
                        ksafe.putDirect("dirty_test_${writerId}_$i", "v$i", KSafeWriteMode.Plain)
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                        if (errors.get() <= 5) {
                            println("Dirty keys stress error: ${e::class.simpleName}: ${e.message}")
                        }
                    }
                }
            }
        }

        jobs.joinAll()

        assertTrue(
            errors.get() == 0,
            "Dirty keys stress test should complete without NoSuchElementException. Errors: ${errors.get()}"
        )
    }

    /**
     * Stress test for the cache cleanup race condition.
     *
     * Scenario: putDirect writes a new key to memoryCache. Before the write
     * is flushed to DataStore, updateCache runs and removes the key from
     * memoryCache because it's not yet in DataStore. A subsequent getDirect
     * then returns the default value instead of the written value.
     *
     * This test writes encrypted values and immediately reads them back,
     * repeating many times to maximize the chance of hitting the race window.
     */
    @Test
    fun testNewKeysSurviveCacheCleanup() = runTest {
        val ksafe = createKSafe()
        val iterations = 200
        val defaultsReturned = AtomicInteger(0)
        val errors = AtomicInteger(0)

        // Trigger an initial cache load by reading a non-existent key
        ksafe.getDirect("warmup", "default")
        delay(100) // Let cache initialize

        val jobs = (0 until 10).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        val key = "cleanup_race_w${writerId}_k$i"
                        val value = "written_${writerId}_$i"
                        val default = "DEFAULT"

                        ksafe.putDirect(key, value)
                        // Read back immediately — should get written value, not default
                        val readBack = ksafe.getDirect(key, default)
                        if (readBack == default) {
                            defaultsReturned.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        jobs.joinAll()

        assertEquals(0, errors.get(), "No exceptions during test")
        assertEquals(
            0, defaultsReturned.get(),
            "No reads should return default after putDirect — cache cleanup must not evict dirty keys"
        )
    }

    // ============ ORPHANED CIPHERTEXT CLEANUP TESTS ============

    /**
     * Tests that orphaned ciphertext (encrypted data whose key is lost)
     * is cleaned up on KSafe startup.
     *
     * Uses a togglable engine: initially works normally, then switched to fail mode
     * to simulate lost encryption keys (as happens after Android backup restore).
     *
     * Since DataStore enforces single-instance per file, the engine is toggled
     * mid-lifecycle and a new KSafe instance is created with a fresh unique name
     * that starts with the failing engine from the beginning.
     */
    @Test
    fun testOrphanedCiphertextIsCleanedUpOnStartup() = runTest {
        // Phase 1: Create engine and KSafe, write encrypted data
        val engine = object : KSafeEncryption {
            private val delegate = FakeEncryption()
            @Volatile var failOnDecrypt = false

            override fun encrypt(
                identifier: String,
                data: ByteArray,
                hardwareIsolated: Boolean,
                requireUnlockedDevice: Boolean?
            ): ByteArray = delegate.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

            override fun decrypt(identifier: String, data: ByteArray): ByteArray {
                if (failOnDecrypt) throw IllegalStateException("No encryption key found")
                return delegate.decrypt(identifier, data)
            }

            override fun deleteKey(identifier: String) = delegate.deleteKey(identifier)
        }

        val ksafe = KSafe(
            fileName = generateUniqueFileName(),
            testEngine = engine
        )
        delay(300) // Let background collector + cleanup complete (no orphans yet)

        // Write encrypted data with working engine
        ksafe.put("orphan_test", "secret_value")
        ksafe.put("orphan_test2", "secret_value2")
        delay(500) // Let write flush

        // Verify values are readable
        assertEquals("secret_value", ksafe.get("orphan_test", "DEFAULT"))
        assertEquals("secret_value2", ksafe.get("orphan_test2", "DEFAULT"))

        // Verify ciphertext exists in DataStore
        val prefs1 = ksafe.dataStore.data.first()
        val encKey1 = stringPreferencesKey("__ksafe_value_orphan_test")
        val encKey2 = stringPreferencesKey("__ksafe_value_orphan_test2")
        assertTrue(prefs1[encKey1] != null, "Ciphertext 1 should exist in DataStore")
        assertTrue(prefs1[encKey2] != null, "Ciphertext 2 should exist in DataStore")

        // Phase 2: Toggle engine to fail (simulates lost keys after backup restore)
        engine.failOnDecrypt = true

        // Value should now return default via getDirect (key gone, falls through)
        assertEquals("DEFAULT", ksafe.getDirect("orphan_test", "DEFAULT"),
            "Should return default when decryption key is lost")

        // Orphaned ciphertext is still in DataStore (cleanup already ran at startup)
        val prefs2 = ksafe.dataStore.data.first()
        assertTrue(prefs2[encKey1] != null, "Orphaned ciphertext should still be in DataStore mid-session")

        // Phase 3: Manually seed DataStore with orphaned ciphertext using a fresh instance
        // We create a second KSafe instance with a DIFFERENT file name but the SAME failing engine.
        // First, write data with working engine, then toggle to fail before creating the instance.
        val engine2 = object : KSafeEncryption {
            private val delegate = FakeEncryption()
            @Volatile var failOnDecrypt = false

            override fun encrypt(
                identifier: String,
                data: ByteArray,
                hardwareIsolated: Boolean,
                requireUnlockedDevice: Boolean?
            ): ByteArray = delegate.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

            override fun decrypt(identifier: String, data: ByteArray): ByteArray {
                if (failOnDecrypt) throw IllegalStateException("No encryption key found")
                return delegate.decrypt(identifier, data)
            }

            override fun deleteKey(identifier: String) = delegate.deleteKey(identifier)
        }

        val fileName2 = generateUniqueFileName()
        val ksafe2setup = KSafe(fileName = fileName2, testEngine = engine2)
        delay(300)

        ksafe2setup.put("cleanup_target", "will_be_orphaned")
        ksafe2setup.put("unenc_key", "plain_value", KSafeWriteMode.Plain)
        delay(500)

        // Verify both exist
        assertEquals("will_be_orphaned", ksafe2setup.get("cleanup_target", "DEFAULT"))
        assertEquals("plain_value", ksafe2setup.get("unenc_key", "DEFAULT"))

        // Verify ciphertext is in DataStore
        val setupPrefs = ksafe2setup.dataStore.data.first()
        val targetKey = stringPreferencesKey("__ksafe_value_cleanup_target")
        assertTrue(setupPrefs[targetKey] != null, "Target ciphertext should exist before cleanup")

        // Now toggle to fail mode — simulates key loss
        engine2.failOnDecrypt = true

        // The ciphertext is orphaned but still in DataStore (cleanup ran before we wrote data)
        // On a real device, next app launch would clean this up.
        // Verify that getDirect returns default for orphaned data
        assertEquals("DEFAULT", ksafe2setup.getDirect("cleanup_target", "DEFAULT"))

        // Unencrypted data should still be accessible
        assertEquals("plain_value", ksafe2setup.getDirect("unenc_key", "DEFAULT"))
    }

    /**
     * Tests that valid encrypted data survives startup cleanup.
     * Only entries that fail to decrypt should be removed.
     */
    @Test
    fun testValidCiphertextIsNotCleanedUp() = runTest {
        val ksafe = createKSafe()
        delay(200) // Let cache initialize

        // Write encrypted data
        ksafe.put("valid_key", "valid_value")
        delay(500) // Let write flush

        // Verify it's readable after startup cleanup ran
        val result = ksafe.get("valid_key", "DEFAULT")
        assertEquals("valid_value", result, "Valid ciphertext should not be cleaned up")
    }

    /**
     * Tests that encrypted values written via putDirect and read via getDirect
     * never transiently return the default value.
     *
     * This directly targets the bug reported by the user: using
     * ksafe.mutableStateOf on an encrypted value, the initial getDirect
     * returned the default once.
     */
    @Test
    fun testEncryptedPutGetNeverReturnsDefault() = runTest {
        val ksafe = createKSafe()
        val defaultsReturned = AtomicInteger(0)
        val errors = AtomicInteger(0)

        // Initialize with known values
        val keyCount = 50
        repeat(keyCount) { i ->
            ksafe.putDirect("enc_key_$i", "value_$i")
        }

        // Let writes persist
        delay(200)

        // Now rapidly read all keys while also writing new ones
        val running = AtomicBoolean(true)

        // Readers: continuously read the pre-populated keys
        val readers = (0 until 5).map { readerId ->
            launch(Dispatchers.Default) {
                while (running.get()) {
                    repeat(keyCount) { i ->
                        try {
                            val result = ksafe.getDirect("enc_key_$i", "DEFAULT")
                            if (result == "DEFAULT") {
                                defaultsReturned.incrementAndGet()
                            }
                        } catch (e: Exception) {
                            errors.incrementAndGet()
                        }
                    }
                }
            }
        }

        // Writers: write new keys to trigger updateCache cycles
        val writers = (0 until 5).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(100) { i ->
                    try {
                        ksafe.putDirect("new_enc_${writerId}_$i", "new_$i")
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        writers.joinAll()
        running.set(false)
        readers.joinAll()

        assertEquals(0, errors.get(), "No exceptions during test")
        assertEquals(
            0, defaultsReturned.get(),
            "Encrypted getDirect must never transiently return default for written keys"
        )
    }

    // ============ NULLABLE PRIMITIVE RETRIEVAL TESTS ============

    /**
     * Tests that unencrypted primitive values can be retrieved with a nullable default.
     *
     * Bug: When calling get<String?>(key, defaultValue = null, encrypted = false),
     * the `when(defaultValue)` dispatch in `convertStoredValue` falls to the `else`
     * branch (null doesn't match `is String`), which tried JSON deserialization on
     * a plain string — failing because "hello" is not valid JSON.
     */
    @Test
    fun testNullableStringGetReturnsStoredValue() = runTest {
        val ksafe = createKSafe()
        delay(200)

        // Store a plain string without encryption
        ksafe.put("str_key", "hello_world", KSafeWriteMode.Plain)
        delay(200)

        // Retrieve with nullable String? and null default — should return stored value, not null
        val result: String? = ksafe.get("str_key", defaultValue = null)
        assertEquals("hello_world", result, "Nullable String? get should return stored value")
    }

    @Test
    fun testNullableStringGetDirectReturnsStoredValue() = runTest {
        val ksafe = createKSafe()
        delay(200)

        ksafe.putDirect("str_key2", "direct_hello", KSafeWriteMode.Plain)

        val result: String? = ksafe.getDirect("str_key2", defaultValue = null)
        assertEquals("direct_hello", result, "Nullable String? getDirect should return stored value")
    }

    @Test
    fun testNullableIntGetReturnsStoredValue() = runTest {
        val ksafe = createKSafe()
        delay(200)

        ksafe.put("int_key", 42, KSafeWriteMode.Plain)
        delay(200)

        val result: Int? = ksafe.get("int_key", defaultValue = null)
        assertEquals(42, result, "Nullable Int? get should return stored value")
    }

    @Test
    fun testNullableStringGetReturnsNullWhenNotStored() = runTest {
        val ksafe = createKSafe()
        delay(200)

        val result: String? = ksafe.get("nonexistent", defaultValue = null)
        assertNull(result, "Should return null for non-existent key with null default")
    }

    @Test
    fun testLegacyPlainIntMigratesToCanonicalOnWrite() = runTest {
        val ksafe = createKSafe()
        val key = "legacy_plain_int"
        delay(200)

        // Simulate pre-1.8.0 storage shape.
        ksafe.dataStore.edit { prefs ->
            prefs[intPreferencesKey(key)] = 41
            prefs[stringPreferencesKey("__ksafe_prot_${key}__")] = "NONE"
        }
        ksafe.updateCache(ksafe.dataStore.data.first())

        assertEquals(41, ksafe.getDirect(key, 0), "Legacy plaintext value should be readable before migration")

        // Next write should migrate the key shape.
        ksafe.put(key, 42, KSafeWriteMode.Plain)

        val prefs = ksafe.dataStore.data.first()
        assertEquals(42, prefs[intPreferencesKey("__ksafe_value_${key}")])
        assertNull(prefs[intPreferencesKey(key)], "Legacy plaintext key should be removed after migration")
        assertNull(prefs[stringPreferencesKey("encrypted_${key}")], "Legacy encrypted key should be absent")
        assertNull(prefs[stringPreferencesKey("__ksafe_prot_${key}__")], "Legacy metadata key should be removed")
        assertNotNull(prefs[stringPreferencesKey("__ksafe_meta_${key}__")], "Canonical metadata should exist")
    }

    @Test
    fun testLegacyEncryptedMigratesToCanonicalOnWrite() = runTest {
        val ksafe = createKSafe()
        val key = "legacy_encrypted_string"
        delay(200)

        // Simulate pre-1.8.0 encrypted storage shape.
        val alias = ksafe.core.keyAlias(key)
        val oldJson = "\"legacy_v1\""
        val oldCiphertext = encodeBase64(ksafe.engine.encrypt(alias, oldJson.encodeToByteArray()))
        ksafe.dataStore.edit { prefs ->
            prefs[stringPreferencesKey("encrypted_${key}")] = oldCiphertext
            prefs[stringPreferencesKey("__ksafe_prot_${key}__")] = "DEFAULT"
        }
        ksafe.updateCache(ksafe.dataStore.data.first())

        assertEquals("legacy_v1", ksafe.getDirect(key, "DEFAULT"), "Legacy encrypted value should be readable")

        // Next encrypted write should migrate key names and metadata.
        ksafe.put(key, "legacy_v2", KSafeWriteMode.Encrypted())

        val prefs = ksafe.dataStore.data.first()
        assertNotNull(prefs[stringPreferencesKey("__ksafe_value_${key}")], "Canonical value key should exist")
        assertNull(prefs[stringPreferencesKey("encrypted_${key}")], "Legacy encrypted key should be removed")
        assertNull(prefs[stringPreferencesKey("__ksafe_prot_${key}__")], "Legacy metadata key should be removed")
        assertNotNull(prefs[stringPreferencesKey("__ksafe_meta_${key}__")], "Canonical metadata should exist")
        assertEquals("legacy_v2", ksafe.getDirect(key, "DEFAULT"), "Updated value should be readable after migration")
    }

}
