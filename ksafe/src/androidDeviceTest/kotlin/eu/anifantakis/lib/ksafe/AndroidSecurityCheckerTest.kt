package eu.anifantakis.lib.ksafe

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
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
