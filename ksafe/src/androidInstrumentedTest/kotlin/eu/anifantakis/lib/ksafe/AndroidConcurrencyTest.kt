package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * Android-specific concurrency and race condition stress tests.
 *
 * These tests run on a real device/emulator with the Android Keystore,
 * exercising code paths that JVM tests (with FakeEncryption) cannot reach:
 *   - Real Keystore encryption/decryption timing
 *   - Background collector + migration interaction with concurrent reads
 *   - Cache cleanup under real DataStore persistence latency
 */
@RunWith(AndroidJUnit4::class)
class AndroidConcurrencyTest {

    companion object {
        private var counter = 0

        /**
         * Generates a unique file name using only lowercase letters.
         * KSafe requires file names to match regex [a-z]+
         */
        @Synchronized
        private fun uniqueName(): String {
            counter++
            val sb = StringBuilder("conctest")
            var n = System.nanoTime() xor counter.toLong()
            if (n < 0) n = -n
            while (n > 0) {
                sb.append(('a' + (n % 26).toInt()))
                n /= 26
            }
            return sb.toString()
        }
    }

    private fun createKSafe(fileName: String? = null): KSafe {
        val context = ApplicationProvider.getApplicationContext<Context>()
        return KSafe(context, fileName ?: uniqueName())
    }

    // ============ ENCRYPTED putDirect/getDirect STRESS ============

    /**
     * Stress test: encrypted putDirect followed by immediate getDirect.
     *
     * This directly targets the user-reported bug: using ksafe.mutableStateOf
     * on an encrypted value, getDirect returned the default once.
     *
     * On Android with real Keystore, the timing of background collector,
     * migration, and encryption is different from JVM's FakeEncryption.
     */
    @Test
    fun testEncryptedPutGetNeverReturnsDefault() = runTest {
        val ksafe = createKSafe()
        val defaultsReturned = AtomicInteger(0)
        val errors = AtomicInteger(0)
        val iterations = 100

        // Let cache initialize
        delay(200)

        val jobs = (0 until 10).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        val key = "encwkik${writerId}x$i"
                        val value = "written${writerId}x$i"
                        val default = "DEFAULT"

                        ksafe.putDirect(key, value, encrypted = true)
                        val readBack = ksafe.getDirect(key, default, encrypted = true)
                        if (readBack == default) {
                            defaultsReturned.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        jobs.forEach { it.join() }

        assertEquals(0, errors.get(), "No exceptions during encrypted put/get stress")
        assertEquals(
            0, defaultsReturned.get(),
            "Encrypted getDirect must never return default after putDirect"
        )
    }

    /**
     * Tests that pre-populated encrypted values are never transiently lost
     * when concurrent writes trigger DataStore emissions and cache refreshes.
     */
    @Test
    fun testExistingEncryptedValuesStableDuringConcurrentWrites() = runTest {
        val ksafe = createKSafe()
        val keyCount = 20
        val defaultsReturned = AtomicInteger(0)
        val errors = AtomicInteger(0)

        // Pre-populate encrypted values using suspend put (durable)
        repeat(keyCount) { i ->
            ksafe.put("stablekey$i", "stablevalue$i", encrypted = true)
        }

        // Let persistence complete
        delay(300)

        val running = AtomicBoolean(true)

        // Readers: continuously verify pre-populated keys
        val readers = (0 until 3).map { readerId ->
            launch(Dispatchers.Default) {
                while (running.get()) {
                    repeat(keyCount) { i ->
                        try {
                            val result = ksafe.getDirect("stablekey$i", "DEFAULT", encrypted = true)
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

        // Writers: write NEW keys to trigger cache refresh cycles
        val writers = (0 until 3).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(50) { i ->
                    try {
                        ksafe.putDirect("churn${writerId}x$i", "churn$i", encrypted = true)
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        writers.forEach { it.join() }
        running.set(false)
        readers.forEach { it.join() }

        assertEquals(0, errors.get(), "No exceptions during concurrent read/write")
        assertEquals(
            0, defaultsReturned.get(),
            "Existing encrypted values must never transiently return default during concurrent writes"
        )
    }

    // ============ MIXED ENCRYPTED/UNENCRYPTED STRESS ============

    /**
     * Stress test mixing encrypted and unencrypted operations on the same KSafe instance.
     * This exercises the cache handling for both key prefixes simultaneously.
     */
    @Test
    fun testMixedEncryptedUnencryptedStress() = runTest {
        val ksafe = createKSafe()
        val errors = AtomicInteger(0)
        val iterations = 50

        delay(200) // Let cache init

        val jobs = (0 until 5).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        val key = "mixedwki${writerId}x$i"
                        val encValue = "encrypted${writerId}x$i"
                        val plainValue = "plain${writerId}x$i"

                        ksafe.putDirect(key, encValue, encrypted = true)
                        ksafe.putDirect("plain$key", plainValue, encrypted = false)

                        // Read back both
                        val encRead = ksafe.getDirect(key, "ENCDEFAULT", encrypted = true)
                        val plainRead = ksafe.getDirect("plain$key", "PLAINDEFAULT", encrypted = false)

                        if (encRead == "ENCDEFAULT" || plainRead == "PLAINDEFAULT") {
                            errors.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        jobs.forEach { it.join() }

        assertEquals(
            0, errors.get(),
            "Mixed encrypted/unencrypted operations should never return defaults"
        )
    }

    // ============ RAPID OVERWRITE STRESS ============

    /**
     * Rapidly overwrites the same encrypted key from multiple coroutines.
     * After all writes, the final value should be one of the written values (not the default).
     */
    @Test
    fun testRapidOverwriteSameEncryptedKey() = runTest {
        val ksafe = createKSafe()
        val errors = AtomicInteger(0)
        val key = "contendedkey"
        val default = "DEFAULT"

        delay(200)

        // Write initial value
        ksafe.putDirect(key, "initial", encrypted = true)

        // Rapid overwrite from multiple coroutines
        val jobs = (0 until 10).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(50) { i ->
                    try {
                        ksafe.putDirect(key, "w${writerId}i$i", encrypted = true)
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        jobs.forEach { it.join() }

        // The value should be SOMETHING written, never the default
        val finalValue = ksafe.getDirect(key, default, encrypted = true)
        assertNotEquals(default, finalValue, "Contended key must never revert to default")
        assertEquals(0, errors.get(), "No exceptions during rapid overwrite")
    }

    // ============ putDirect PERSISTENCE VERIFICATION ============

    /**
     * Verifies that values written via putDirect are eventually persisted to DataStore
     * and readable via the suspend get API (which reads DataStore directly when cache
     * is not yet initialized).
     */
    @Test
    fun testPutDirectEventuallyPersists() = runTest {
        val ksafe = createKSafe()

        delay(200)

        // Write via putDirect
        ksafe.putDirect("persistkey", "persistvalue", encrypted = true)

        // Wait for background flush (16ms coalesce + DataStore write)
        delay(1000)

        // Read via suspend get (reads from cache which should have the persisted value)
        val result = ksafe.get("persistkey", "DEFAULT", encrypted = true)
        assertEquals("persistvalue", result, "putDirect value must be readable via suspend get after flush")
    }

    // ============ IMMEDIATE getDirect AFTER INIT ============

    /**
     * Creates a KSafe instance and immediately calls getDirect on a key that
     * doesn't exist yet. This verifies that getDirect returns the default
     * gracefully even when the background collector hasn't finished.
     */
    @Test
    fun testGetDirectBeforeCacheInitReturnsDefault() = runTest {
        val ksafe = createKSafe()
        // No delay — read immediately
        val result = ksafe.getDirect("nonexistent", "DEFAULT", encrypted = true)
        assertEquals("DEFAULT", result, "getDirect on non-existent key should return default")
    }
}
