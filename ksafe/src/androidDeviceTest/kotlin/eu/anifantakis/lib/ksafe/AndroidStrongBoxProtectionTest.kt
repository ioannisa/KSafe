package eu.anifantakis.lib.ksafe

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.KSafeProtectionNotes
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Locks in: what KSafe reports on a device WITH StrongBox versus one WITHOUT — the one
 * per-device difference the rest of the device suite cannot see, since every other test
 * passes identically on both classes.
 *
 * The two capability tests are mutually exclusive by construction ([assumeTrue] /
 * [assumeFalse] on the same probe), so exactly one runs per device and the other is
 * reported skipped: the run report itself records which class the device is in.
 */
@RunWith(AndroidJUnit4::class)
class AndroidStrongBoxProtectionTest {

    private companion object {
        const val TAG = "KSafeStrongBoxTest"
    }

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private val safes = mutableListOf<KSafe>()

    @After
    fun tearDown() {
        safes.forEach { safe ->
            runCatching { runBlocking { safe.clearAll() } }
            runCatching { safe.close() }
        }
        safes.clear()
    }

    private var counter = 0

    private fun newSafe(): KSafe {
        counter++
        return KSafe(context, fileName = "sbprobe_${System.nanoTime()}_$counter").also { safes += it }
    }

    /** What the device itself claims, independent of anything KSafe computed. */
    private val deviceHasStrongBox: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun logBranch(branch: String, info: KSafeProtectionInfo) {
        Log.i(
            TAG,
            "branch=$branch model=${Build.MODEL} api=${Build.VERSION.SDK_INT} " +
                "deviceHasStrongBox=$deviceHasStrongBox intended=${info.intendedLevel} " +
                "effective=${info.effectiveLevel} notes=${info.notes} custody='${info.custody}'",
        )
    }

    /** Writes [value] under an explicit HARDWARE_ISOLATED request and returns its recorded key info. */
    private fun writeIsolatedEntry(safe: KSafe, key: String, value: String): KSafeKeyInfo {
        runBlocking {
            safe.put(key, value, KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
        }
        assertEquals(value, runBlocking { safe.get(key, "") }, "the isolated entry must round-trip")
        return assertNotNull(safe.getKeyInfo(key), "a written entry must have key info")
    }

    /**
     * Runs on EVERY device: the Android instance baseline is the TEE on both device classes.
     * StrongBox is a per-write opt-in, never an instance-level level, so `protectionInfo`'s
     * two levels are equal and HARDWARE_BACKED even where StrongBox exists.
     */
    @Test
    fun baselineLevel_isHardwareBacked_andNeverFallsBack_onEveryDevice() {
        val info = newSafe().protectionInfo
        logBranch("baseline", info)

        assertEquals(KSafeProtectionLevel.HARDWARE_BACKED, info.intendedLevel)
        assertEquals(
            KSafeProtectionLevel.HARDWARE_BACKED,
            info.effectiveLevel,
            "Android negotiates no instance-level fallback; StrongBox is reached per-write only",
        )
        assertTrue(info.isEncryptionOperational, "Android encryption must always be operational")
    }

    /**
     * StrongBox devices only. The capability is advertised, the absent-note is withheld, and a
     * HARDWARE_ISOLATED write must land in a key whose custody the API 31+ probe verifies as
     * StrongBox — a silent StrongBox-to-TEE fallback would report HARDWARE_BACKED here.
     */
    @Test
    fun strongBoxDevice_advertisesIsolatedTier_andIsolatedWriteGetsAnIsolatedKey() {
        assumeTrue("device has no StrongBox; the no-StrongBox twin covers this class", deviceHasStrongBox)

        val safe = newSafe()
        val info = safe.protectionInfo
        logBranch("strongbox", info)

        assertFalse(
            info.notes.contains(KSafeProtectionNotes.ANDROID_STRONGBOX_ABSENT),
            "a StrongBox device must not report the absent note; notes=${info.notes}",
        )
        assertTrue(
            safe.deviceKeyStorages.contains(KSafeKeyStorage.HARDWARE_ISOLATED),
            "a StrongBox device must advertise the isolated tier; was ${safe.deviceKeyStorages}",
        )
        assertTrue(
            info.custody.contains("StrongBox"),
            "custody should mention StrongBox availability; was '${info.custody}'",
        )

        val keyInfo = writeIsolatedEntry(safe, "isolated_entry", "isolated-value")
        assertEquals(KSafeProtection.HARDWARE_ISOLATED, keyInfo.protection)
        assertEquals(
            KSafeProtectionLevel.HARDWARE_ISOLATED,
            keyInfo.level,
            "an isolated write on a StrongBox device must be served by a StrongBox key",
        )
    }

    /**
     * Non-StrongBox devices only. The absent-note is present, the isolated tier is not
     * advertised, and a HARDWARE_ISOLATED write is honestly downgraded: the REQUEST stays
     * recorded as HARDWARE_ISOLATED while the key's actual level reports the TEE.
     */
    @Test
    fun noStrongBoxDevice_reportsAbsentNote_andDowngradesIsolatedWriteToTee() {
        assumeFalse("device has StrongBox; the StrongBox twin covers this class", deviceHasStrongBox)

        val safe = newSafe()
        val info = safe.protectionInfo
        logBranch("no-strongbox", info)

        assertTrue(
            info.notes.contains(KSafeProtectionNotes.ANDROID_STRONGBOX_ABSENT),
            "a device without StrongBox must report the absent note; notes=${info.notes}",
        )
        assertEquals(
            setOf(KSafeKeyStorage.HARDWARE_BACKED),
            safe.deviceKeyStorages,
            "without StrongBox the isolated tier must not be advertised",
        )
        assertFalse(
            info.custody.contains("StrongBox"),
            "custody must not claim StrongBox availability; was '${info.custody}'",
        )

        val keyInfo = writeIsolatedEntry(safe, "isolated_entry", "isolated-value")
        assertEquals(
            KSafeProtection.HARDWARE_ISOLATED,
            keyInfo.protection,
            "the requested tier stays recorded even when the device cannot honor it",
        )
        assertEquals(
            KSafeProtectionLevel.HARDWARE_BACKED,
            keyInfo.level,
            "without StrongBox an isolated write must report the honest TEE level",
        )
    }
}
