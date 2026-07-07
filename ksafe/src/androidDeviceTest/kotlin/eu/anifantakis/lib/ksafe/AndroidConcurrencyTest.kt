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

/** Locks in: encrypted putDirect/getDirect and mixed read/write stress on the real Android Keystore never transiently return the default. */
@RunWith(AndroidJUnit4::class)
class AndroidConcurrencyTest {

    companion object {
        private var counter = 0

        /** Unique lowercase-only file name (KSafe requires file names to match [a-z]+). */
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

    /** Encrypted putDirect then immediate getDirect must never transiently return the default (the mutableStateOf initial-read scenario). */
    @Test
    fun testEncryptedPutGetNeverReturnsDefault() = runTest {
        val ksafe = createKSafe()
        val defaultsReturned = AtomicInteger(0)
        val errors = AtomicInteger(0)
        val iterations = 100

        delay(200)

        val jobs = (0 until 10).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        val key = "encwkik${writerId}x$i"
                        val value = "written${writerId}x$i"
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

        assertEquals(0, errors.get(), "No exceptions during encrypted put/get stress")
        assertEquals(
            0, defaultsReturned.get(),
            "Encrypted getDirect must never return default after putDirect"
        )
    }

    /** Pre-populated encrypted values must never transiently vanish while concurrent writes trigger DataStore emissions and cache refreshes. */
    @Test
    fun testExistingEncryptedValuesStableDuringConcurrentWrites() = runTest {
        val ksafe = createKSafe()
        val keyCount = 20
        val defaultsReturned = AtomicInteger(0)
        val errors = AtomicInteger(0)

        repeat(keyCount) { i ->
            ksafe.put("stablekey$i", "stablevalue$i")
        }

        delay(300)

        val running = AtomicBoolean(true)

        val readers = (0 until 3).map { readerId ->
            launch(Dispatchers.Default) {
                while (running.get()) {
                    repeat(keyCount) { i ->
                        try {
                            val result = ksafe.getDirect("stablekey$i", "DEFAULT")
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

        // Writers churn NEW keys to trigger cache-refresh cycles.
        val writers = (0 until 3).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(50) { i ->
                    try {
                        ksafe.putDirect("churn${writerId}x$i", "churn$i")
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        writers.joinAll()
        running.set(false)
        readers.joinAll()

        assertEquals(0, errors.get(), "No exceptions during concurrent read/write")
        assertEquals(
            0, defaultsReturned.get(),
            "Existing encrypted values must never transiently return default during concurrent writes"
        )
    }

    /** Mixed encrypted + unencrypted ops on one KSafe exercise cache handling for both key prefixes at once. */
    @Test
    fun testMixedEncryptedUnencryptedStress() = runTest {
        val ksafe = createKSafe()
        val errors = AtomicInteger(0)
        val iterations = 50

        delay(200)

        val jobs = (0 until 5).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(iterations) { i ->
                    try {
                        val key = "mixedwki${writerId}x$i"
                        val encValue = "encrypted${writerId}x$i"
                        val plainValue = "plain${writerId}x$i"

                        ksafe.putDirect(key, encValue)
                        ksafe.putDirect("plain$key", plainValue, KSafeWriteMode.Plain)

                        val encRead = ksafe.getDirect(key, "ENCDEFAULT")
                        val plainRead = ksafe.getDirect("plain$key", "PLAINDEFAULT")

                        if (encRead == "ENCDEFAULT" || plainRead == "PLAINDEFAULT") {
                            errors.incrementAndGet()
                        }
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        jobs.joinAll()

        assertEquals(
            0, errors.get(),
            "Mixed encrypted/unencrypted operations should never return defaults"
        )
    }

    /** Rapid concurrent overwrites of one encrypted key must leave a written value, never the default. */
    @Test
    fun testRapidOverwriteSameEncryptedKey() = runTest {
        val ksafe = createKSafe()
        val errors = AtomicInteger(0)
        val key = "contendedkey"
        val default = "DEFAULT"

        delay(200)

        ksafe.putDirect(key, "initial")

        val jobs = (0 until 10).map { writerId ->
            launch(Dispatchers.Default) {
                repeat(50) { i ->
                    try {
                        ksafe.putDirect(key, "w${writerId}i$i")
                    } catch (e: Exception) {
                        errors.incrementAndGet()
                    }
                }
            }
        }

        jobs.joinAll()

        val finalValue = ksafe.getDirect(key, default)
        assertNotEquals(default, finalValue, "Contended key must never revert to default")
        assertEquals(0, errors.get(), "No exceptions during rapid overwrite")
    }

    /** putDirect values are eventually persisted and readable via the suspend get API. */
    @Test
    fun testPutDirectEventuallyPersists() = runTest {
        val ksafe = createKSafe()

        delay(200)

        ksafe.putDirect("persistkey", "persistvalue")

        // Wait for the background flush (16ms coalesce + DataStore write).
        delay(1000)

        val result = ksafe.get("persistkey", "DEFAULT")
        assertEquals("persistvalue", result, "putDirect value must be readable via suspend get after flush")
    }

    /** getDirect on a missing key returns the default gracefully even before the background collector finishes. */
    @Test
    fun testGetDirectBeforeCacheInitReturnsDefault() = runTest {
        val ksafe = createKSafe()
        // No delay — read before the collector initializes.
        val result = ksafe.getDirect("nonexistent", "DEFAULT")
        assertEquals("DEFAULT", result, "getDirect on non-existent key should return default")
    }
}
