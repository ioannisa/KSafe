package eu.anifantakis.lib.ksafe

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.isEmulatorBuild
import eu.anifantakis.lib.ksafe.internal.isRootIndicatingBuild
import org.junit.runner.RunWith
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Locks in: the root-detection build signal — build type (userdebug/eng), not signing tag, marks a root-capable image, so rooted userdebug emulators aren't missed and user-build dev-keys emulators aren't false-flagged. */
@RunWith(AndroidJUnit4::class)
class AndroidSecurityCheckerTest {

    @Test
    fun userdebugAndEngBuildsAreRootIndicating() {
        assertTrue(isRootIndicatingBuild("userdebug", "release-keys"))
        assertTrue(isRootIndicatingBuild("eng", "release-keys"))
        // userdebug Google-APIs emulator image (su present, adb root works)
        assertTrue(isRootIndicatingBuild("userdebug", "dev-keys"))
    }

    @Test
    fun testKeysAreRootIndicating() {
        assertTrue(isRootIndicatingBuild("user", "test-keys"))
    }

    @Test
    fun userBuildEmulatorWithDevKeysIsNotRootIndicating() {
        // Google Play / foldable images are user + dev-keys but ship no su — dev-keys must
        // NOT count as root, or they false-positive.
        assertFalse(isRootIndicatingBuild("user", "dev-keys"))
    }

    @Test
    fun productionUserReleaseBuildIsNotRootIndicating() {
        assertFalse(isRootIndicatingBuild("user", "release-keys"))
        assertFalse(isRootIndicatingBuild(null, null))
    }

    @Test
    fun rootCapableImageIsReportedAsRooted() {
        // On a root-capable image (userdebug/eng), isDeviceRooted() must agree; on a user
        // build the precondition is false and this is skipped.
        if (isRootIndicatingBuild(Build.TYPE, Build.TAGS)) {
            assertTrue(
                SecurityChecker.isDeviceRooted(),
                "Build.TYPE=${Build.TYPE}, TAGS=${Build.TAGS} is root-capable " +
                    "but isDeviceRooted() returned false"
            )
        }
    }

    @Test
    fun physicalUserdebugTestKeysDeviceIsNotAnEmulator() {
        // A physical engineering device (userdebug/test-keys retail hardware) is correctly
        // flagged root-capable, but must not ALSO trip the emulator probe: build type and
        // signing tags are root signals, not emulator signals.
        assertFalse(
            isEmulatorBuild(
                fingerprint = "samsung/dm3qxxx/dm3q:14/UP1A.231005.007/S918BXXU3AWK7:userdebug/test-keys",
                model = "SM-S918B",
                manufacturer = "samsung",
                brand = "samsung",
                device = "dm3q",
                product = "dm3qxxx",
                hardware = "qcom",
                board = "kalama",
                id = "UP1A.231005.007",
            ),
            "a physical userdebug/test-keys build must not be classified as an emulator",
        )
    }

    @Test
    fun emulatorImagesAreStillDetectedByHardwareSignals() {
        // Modern Google emulator (ranchu) and legacy goldfish images keep tripping the probe
        // through hardware/product signals alone — no build-type/tag clause needed.
        assertTrue(
            isEmulatorBuild(
                fingerprint = "google/sdk_gphone64_arm64/emu64a:14/UE1A.230829.036/11228894:user/dev-keys",
                model = "sdk_gphone64_arm64",
                manufacturer = "Google",
                brand = "google",
                device = "emu64a",
                product = "sdk_gphone64_arm64",
                hardware = "ranchu",
                board = "goldfish_arm64",
                id = "UE1A.230829.036",
            ),
        )
        assertTrue(
            isEmulatorBuild(
                fingerprint = "generic/sdk/generic:4.4/KRT16/eng.build:eng/test-keys",
                model = "sdk",
                manufacturer = "unknown",
                brand = "generic",
                device = "generic",
                product = "sdk",
                hardware = "goldfish",
                board = "unknown",
                id = "KRT16",
            ),
        )
    }

    @Test
    fun nonRootedUserBuildEmulatorIsNotReportedAsRooted() {
        // A user-build emulator must not be flagged. Guarded to emulators (never a real
        // rooted retail device) and excludes test-keys.
        val tags = Build.TAGS ?: ""
        if (SecurityChecker.isEmulator() && Build.TYPE == "user" && !tags.contains("test-keys")) {
            assertFalse(
                SecurityChecker.isDeviceRooted(),
                "user-build emulator (TYPE=${Build.TYPE}, TAGS=${Build.TAGS}) " +
                    "must not be reported as rooted"
            )
        }
    }
}
