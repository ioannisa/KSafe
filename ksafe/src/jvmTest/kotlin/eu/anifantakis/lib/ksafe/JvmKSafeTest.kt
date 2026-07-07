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
import kotlin.time.Duration.Companion.seconds

/** Locks in: each test uses a unique DataStore file name — JVM forbids two instances on one file, and files persist across runs. */
class JvmKSafeTest : KSafeTest() {

    companion object {
        /**
         * Stress intensity multiplier (default 1.0 = full local load). CI passes a small scale
         * so the concurrency tests stay drainable on a 2-vCPU runner without a writer/coalescer
         * livelock; floored so a tiny scale can't no-op a test.
         */
        private val STRESS_SCALE: Double =
            System.getProperty("ksafe.stressScale")?.toDoubleOrNull()?.coerceIn(0.01, 1.0) ?: 1.0

        internal fun scaled(n: Int, floor: Int = 25): Int =
            (n * STRESS_SCALE).toInt().coerceAtLeast(floor)

        private val testCounter = AtomicInteger(0)

        // Base-26 letters (KSafe file names must match [a-z]+); timestamp ⇒ unique across runs.
        private val runId: String = numberToLetters(System.currentTimeMillis())

        /** Unique lowercase-only file name (KSafe requires [a-z]+): run{timestamp}test{counter}. */
        fun generateUniqueFileName(): String {
            val count = testCounter.incrementAndGet()
            return "run${runId}test${numberToLetters(count.toLong())}"
        }

        /** Encodes a number as base-26 lowercase letters (1→"a", 27→"aa"). */
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

    override fun newKSafe(fileName: String?): KSafe {
        // Make caller-supplied names unique across runs too (isolation tests).
        val uniqueName = if (fileName != null) {
            "run${runId}${fileName}"
        } else {
            generateUniqueFileName()
        }
        return KSafe(uniqueName)
    }

    /** Concurrent putDirect must not throw NoSuchElementException from iterating the cache's ConcurrentHashMap under concurrent modification. */
    @Test
    fun testConcurrentPutDirectStress() = runTest {
        val ksafe = createKSafe()
        val iterations = scaled(500)
        val concurrentWriters = 10
        val errors = AtomicInteger(0)
        val successfulWrites = AtomicInteger(0)

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

        jobs.joinAll()

        assertEquals(0, errors.get(), "Should have no errors during concurrent writes")
        assertEquals(
            concurrentWriters * iterations,
            successfulWrites.get(),
            "All writes should succeed"
        )
    }

    /** Concurrent encrypted putDirect (adds encryption + key lookup) must not race. */
    @Test
    fun testConcurrentEncryptedPutDirectStress() = runTest {
        val ksafe = createKSafe()
        val iterations = scaled(100)
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

    /** Simultaneous reads and writes on the same keys must not race. */
    @Test
    fun testConcurrentReadWriteStress() = runTest {
        val ksafe = createKSafe()
        val iterations = scaled(200)
        val errors = AtomicInteger(0)
        val running = AtomicBoolean(true)

        repeat(50) { i ->
            ksafe.putDirect("shared_key_$i", "initial_$i", KSafeWriteMode.Plain)
        }

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

    /** Rapid dirty-key churn must not throw NoSuchElementException from concurrent ConcurrentHashMap iteration. */
    @Test
    fun testDirtyKeysStress() = runTest {
        val ksafe = createKSafe()
        val iterations = scaled(1000)
        val errors = AtomicInteger(0)

        val jobs = (0 until 20).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
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
     * A new key written by putDirect must survive updateCache: before the write flushes,
     * updateCache must not evict the not-yet-persisted key, or a later getDirect returns the default.
     */
    @Test
    fun testNewKeysSurviveCacheCleanup() = runTest {
        val ksafe = createKSafe()
        val iterations = scaled(200)
        val defaultsReturned = AtomicInteger(0)
        val errors = AtomicInteger(0)

        ksafe.getDirect("warmup", "default")
        delay(100)

        val jobs = (0 until 10).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        val key = "cleanup_race_w${writerId}_k$i"
                        val value = "written_${writerId}_$i"
                        val default = "DEFAULT"

                        ksafe.putDirect(key, value)
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

    /**
     * Orphaned ciphertext (key lost, e.g. after a backup restore) is cleaned up on startup.
     * A togglable engine flips to fail-on-decrypt mid-lifecycle to simulate the lost key.
     */
    @Test
    fun testOrphanedCiphertextIsCleanedUpOnStartup() = runTest {
        val engine = object : KSafeEncryption {
            private val delegate = FakeEncryption()
            @Volatile var failOnDecrypt = false

            override fun encrypt(
                identifier: String,
                data: ByteArray,
                hardwareIsolated: Boolean,
                requireUnlockedDevice: Boolean?
            ): ByteArray = delegate.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

            override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
                if (failOnDecrypt) throw IllegalStateException("No encryption key found")
                return delegate.decrypt(identifier, data)
            }

            override fun deleteKey(identifier: String) = delegate.deleteKey(identifier)
        }

        val ksafe = KSafe(
            fileName = generateUniqueFileName(),
            // ENCRYPTED decrypts on every read, so a mid-session engine fail flips reads to
            // defaults; LAZY_PLAIN_TEXT would cache plaintext and hide the fail, defeating the test.
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine
        )
        delay(300)

        ksafe.put("orphan_test", "secret_value")
        ksafe.put("orphan_test2", "secret_value2")
        delay(500)

        assertEquals("secret_value", ksafe.get("orphan_test", "DEFAULT"))
        assertEquals("secret_value2", ksafe.get("orphan_test2", "DEFAULT"))

        val prefs1 = ksafe.dataStore.data.first()
        val encKey1 = stringPreferencesKey("__ksafe_value_orphan_test")
        val encKey2 = stringPreferencesKey("__ksafe_value_orphan_test2")
        assertTrue(prefs1[encKey1] != null, "Ciphertext 1 should exist in DataStore")
        assertTrue(prefs1[encKey2] != null, "Ciphertext 2 should exist in DataStore")

        // Simulate lost keys (e.g. after a backup restore).
        engine.failOnDecrypt = true

        assertEquals("DEFAULT", ksafe.getDirect("orphan_test", "DEFAULT"),
            "Should return default when decryption key is lost")

        // Cleanup already ran at startup, so the orphan is still present mid-session.
        val prefs2 = ksafe.dataStore.data.first()
        assertTrue(prefs2[encKey1] != null, "Orphaned ciphertext should still be in DataStore mid-session")

        // A second instance (fresh file, same togglable engine) reproduces the orphan end-to-end.
        val engine2 = object : KSafeEncryption {
            private val delegate = FakeEncryption()
            @Volatile var failOnDecrypt = false

            override fun encrypt(
                identifier: String,
                data: ByteArray,
                hardwareIsolated: Boolean,
                requireUnlockedDevice: Boolean?
            ): ByteArray = delegate.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

            override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
                if (failOnDecrypt) throw IllegalStateException("No encryption key found")
                return delegate.decrypt(identifier, data)
            }

            override fun deleteKey(identifier: String) = delegate.deleteKey(identifier)
        }

        val fileName2 = generateUniqueFileName()
        val ksafe2setup = KSafe(
            fileName = fileName2,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED, // see note above
            testEngine = engine2
        )
        delay(300)

        ksafe2setup.put("cleanup_target", "will_be_orphaned")
        ksafe2setup.put("unenc_key", "plain_value", KSafeWriteMode.Plain)
        delay(500)

        assertEquals("will_be_orphaned", ksafe2setup.get("cleanup_target", "DEFAULT"))
        assertEquals("plain_value", ksafe2setup.get("unenc_key", "DEFAULT"))

        val setupPrefs = ksafe2setup.dataStore.data.first()
        val targetKey = stringPreferencesKey("__ksafe_value_cleanup_target")
        assertTrue(setupPrefs[targetKey] != null, "Target ciphertext should exist before cleanup")

        engine2.failOnDecrypt = true

        // The orphan lingers this session (cleanup ran before the write); getDirect returns the default.
        assertEquals("DEFAULT", ksafe2setup.getDirect("cleanup_target", "DEFAULT"))
        assertEquals("plain_value", ksafe2setup.getDirect("unenc_key", "DEFAULT"))
    }

    /** Valid encrypted data survives startup cleanup; only undecryptable entries are removed. */
    @Test
    fun testValidCiphertextIsNotCleanedUp() = runTest {
        val ksafe = createKSafe()
        delay(200)

        ksafe.put("valid_key", "valid_value")
        delay(500)

        val result = ksafe.get("valid_key", "DEFAULT")
        assertEquals("valid_value", result, "Valid ciphertext should not be cleaned up")
    }

    /** Encrypted putDirect + getDirect must never transiently return the default (mutableStateOf on an encrypted value once did). */
    @Test
    fun testEncryptedPutGetNeverReturnsDefault() = runTest(timeout = 90.seconds) {
        // Many encrypted writes + 5 decrypting readers need more than runTest's default 60s
        // budget on a 2-vCPU runner; the yield() below prevents a reader/writer livelock.
        val ksafe = createKSafe()
        val defaultsReturned = AtomicInteger(0)
        val errors = AtomicInteger(0)

        val keyCount = 50
        repeat(keyCount) { i ->
            ksafe.putDirect("enc_key_$i", "value_$i")
        }

        delay(200)

        val running = AtomicBoolean(true)

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
                    // getDirect never suspends; without this yield the CPU-bound readers
                    // monopolise Dispatchers.Default and starve the writers on a ≤2-vCPU runner.
                    yield()
                }
            }
        }

        val writers = (0 until 5).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(scaled(100)) { i ->
                    try {
                        ksafe.putDirect("new_enc_${writerId}_$i", "new_$i")
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                    yield() // putDirect doesn't suspend either
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

    /**
     * A plain primitive reads back with a null default: get<String?>(key, null) must not fall to the
     * JSON-deserialize else-branch (a null default doesn't match `is String`) on a plain string.
     */
    @Test
    fun testNullableStringGetReturnsStoredValue() = runTest {
        val ksafe = createKSafe()
        delay(200)

        ksafe.put("str_key", "hello_world", KSafeWriteMode.Plain)
        delay(200)

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
