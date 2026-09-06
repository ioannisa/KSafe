package eu.anifantakis.lib.ksafe

import android.content.Context
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.time.TimeSource

/**
 * Measures what `rotateKeys()` costs on a real device. There is no pass/fail threshold — hardware,
 * thermal state and other load move the numbers too much — so it asserts only that every entry
 * rotates, and reports timings to logcat under the ROTSCALE tag (`adb logcat -s ROTSCALE`). DEFAULT
 * and HARDWARE_ISOLATED are measured apart: the latter pays a TEE round-trip per entry.
 */
@RunWith(AndroidJUnit4::class)
class AndroidRotationScalingTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private fun measure(entries: Int, mode: KSafeWriteMode, label: String) = runBlocking {
        // Store names take lowercase letters, digits and underscores only.
        val fileName = "rotscale_${label.lowercase()}_${entries}_${System.nanoTime()}"
        val ksafe = KSafe(context, fileName)
        try {
            repeat(entries) { ksafe.put("k$it", "value-number-$it", mode) }

            val mark = TimeSource.Monotonic.markNow()
            val result = ksafe.rotateKeys()
            val elapsed = mark.elapsedNow()

            val perEntryUs = elapsed.inWholeMicroseconds / entries
            Log.i(
                "ROTSCALE",
                "$label entries=$entries " +
                    "elapsed=${elapsed.inWholeMilliseconds}ms " +
                    "perEntry=${perEntryUs}us " +
                    "rotated=${result.rotated} skipped=${result.skipped} failed=${result.failed} " +
                    "generation=${result.keyGeneration}"
            )

            assertEquals(0, result.failed, "$label/$entries: no entry may fail to rotate")
            assertEquals(
                entries, result.rotated + result.skipped,
                "$label/$entries: every entry must be accounted for",
            )
            // Rotation must never touch the values; spot-check both ends.
            assertEquals("value-number-0", ksafe.get("k0", ""), "first value survived rotation")
            assertEquals(
                "value-number-${entries - 1}", ksafe.get("k${entries - 1}", ""),
                "last value survived rotation",
            )
        } finally {
            runCatching { ksafe.clearAll() }
            ksafe.close()
        }
    }

    @Test
    fun defaultEncryption_50() = measure(50, KSafeWriteMode.Encrypted(), "DEFAULT")

    @Test
    fun defaultEncryption_100() = measure(100, KSafeWriteMode.Encrypted(), "DEFAULT")

    @Test
    fun defaultEncryption_200() = measure(200, KSafeWriteMode.Encrypted(), "DEFAULT")

    @Test
    fun defaultEncryption_500() = measure(500, KSafeWriteMode.Encrypted(), "DEFAULT")

    /** The per-entry-Keystore-key case, at one size, so the TEE cost per entry is visible. */
    @Test
    fun hardwareIsolated_50() = measure(
        50, KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED), "HW_ISOLATED",
    )
}
