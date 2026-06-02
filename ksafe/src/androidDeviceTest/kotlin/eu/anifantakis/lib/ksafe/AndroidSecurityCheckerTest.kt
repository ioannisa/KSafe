package eu.anifantakis.lib.ksafe

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.isRootIndicatingBuild
import org.junit.runner.RunWith
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Verifies the Android root-detection build-signal logic.
 *
 * Guards two opposite mistakes:
 *  - the false negative: a rooted `userdebug` Google-APIs emulator (su present, `adb
 *    root` works) reporting "not rooted" because detection only matched `test-keys`
 *    and relied on sandbox-blocked file/`getprop` probes; and
 *  - the false positive: a `user`-build emulator (Google Play / "Pixel 10 Pro Fold"
 *    images — no su, `ro.debuggable=0`) reporting "rooted" just because it is signed
 *    `dev-keys`. The build *type*, not the signing tag, is the real signal.
 */
@RunWith(AndroidJUnit4::class)
class AndroidSecurityCheckerTest {

    // --- deterministic logic (independent of the host image) ---

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
        // Google Play / "Pixel 10 Pro Fold" images are `user` + `dev-keys` but ship no
        // su and refuse `adb root`. dev-keys must NOT be treated as root, or every such
        // emulator false-positives.
        assertFalse(isRootIndicatingBuild("user", "dev-keys"))
    }

    @Test
    fun productionUserReleaseBuildIsNotRootIndicating() {
        assertFalse(isRootIndicatingBuild("user", "release-keys"))
        assertFalse(isRootIndicatingBuild(null, null))
    }

    // --- assertions against the actual device/emulator this runs on ---

    @Test
    fun rootCapableImageIsReportedAsRooted() {
        // If we're on a root-capable image (a userdebug/eng Google-APIs emulator or
        // engineering build), isDeviceRooted() must say so. On a user-build image the
        // precondition is false and the assertion is skipped.
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
        // Counterpart: a `user`-build emulator (Google Play / foldable images — no su,
        // ro.debuggable=0) must NOT be flagged. Guarded to emulators only so it never
        // runs against a genuinely rooted retail device, and excludes test-keys.
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
