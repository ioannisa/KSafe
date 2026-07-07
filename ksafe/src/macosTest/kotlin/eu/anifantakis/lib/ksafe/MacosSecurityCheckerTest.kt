package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: [SecurityChecker] short-circuits on macOS, so the iOS jailbreak path probes
 * (`/bin/sh`, `/etc/apt`, ...) — which all exist on a Mac — don't report every host as
 * rooted and block KSafe under [KSafeSecurityPolicy.Strict].
 */
@OptIn(ExperimentalForeignApi::class)
class MacosSecurityCheckerTest {

    // Guards the isDeviceRooted test below: if the jailbreak probe paths stopped
    // existing on macOS, that test's short-circuit would become vacuous.
    @Test
    fun jailbreakProbePathsExistOnMacosHost() {
        val fm = NSFileManager.defaultManager
        assertTrue(fm.fileExistsAtPath("/bin/sh"), "/bin/sh is expected on every Mac")
    }

    @Test
    fun isDeviceRootedReturnsFalseOnMacos() {
        assertFalse(
            SecurityChecker.isDeviceRooted(),
            "On macOS isDeviceRooted() must be false despite /bin/sh, /etc/apt, etc. " +
                "existing on the host (would otherwise block every Mac with strict policy)."
        )
    }

    @Test
    fun isEmulatorReturnsFalseOnMacos() {
        assertFalse(
            SecurityChecker.isEmulator(),
            "macOS native binary should not be reported as a simulator."
        )
    }

    // Only asserts these don't throw: their boolean answers depend on how the runner
    // was launched (Xcode, gradle, lldb), so no value assertion is stable across runs.
    @Test
    fun debuggerAndDebugBuildChecksDoNotThrow() {
        SecurityChecker.isDebuggerAttached()
        SecurityChecker.isDebugBuild()
    }
}
