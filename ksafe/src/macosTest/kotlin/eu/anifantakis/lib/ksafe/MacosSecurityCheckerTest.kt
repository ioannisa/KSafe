package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Verifies the macOS-specific behaviour of [SecurityChecker].
 *
 * The iOS jailbreak heuristics (`/bin/sh`, `/usr/bin/ssh`, `/etc/apt`, etc.)
 * all fire on every macOS host — Macs ship with `/bin/sh`, Homebrew installs
 * `/etc/apt`-shaped trees, and so on. Without a macOS short-circuit, every
 * Mac would be reported as "rooted" and any KSafe with
 * [KSafeSecurityPolicy.Strict] would refuse to operate.
 */
@OptIn(ExperimentalForeignApi::class)
class MacosSecurityCheckerTest {

    /**
     * Sanity-check: the iOS jailbreak path probes really do exist on macOS.
     * If this assertion ever fails, the [SecurityChecker.isDeviceRooted]
     * test below loses its teeth — the short-circuit becomes vacuous.
     */
    @Test
    fun jailbreakProbePathsExistOnMacosHost() {
        val fm = NSFileManager.defaultManager
        // `/bin/sh` is part of the macOS base install on every supported OS
        // version. If it ever stops existing we have bigger problems.
        assertTrue(fm.fileExistsAtPath("/bin/sh"), "/bin/sh is expected on every Mac")
    }

    /**
     * The core macOS guarantee: even though jailbreak-style paths exist,
     * [SecurityChecker.isDeviceRooted] returns `false`.
     */
    @Test
    fun isDeviceRootedReturnsFalseOnMacos() {
        assertFalse(
            SecurityChecker.isDeviceRooted(),
            "On macOS isDeviceRooted() must be false despite /bin/sh, /etc/apt, etc. " +
                "existing on the host (would otherwise block every Mac with strict policy)."
        )
    }

    /**
     * macOS native binaries are not "the iOS Simulator" — no `SIMULATOR_*`
     * env vars are set. The check should return `false`.
     */
    @Test
    fun isEmulatorReturnsFalseOnMacos() {
        assertFalse(
            SecurityChecker.isEmulator(),
            "macOS native binary should not be reported as a simulator."
        )
    }

    /**
     * The debugger / debug-build heuristics are best-effort. We only assert
     * they don't *throw* on macOS — their boolean answers depend on whether
     * the test runner was launched from Xcode, gradle, lldb, etc., so we
     * can't make a value assertion that's stable across CI and local runs.
     */
    @Test
    fun debuggerAndDebugBuildChecksDoNotThrow() {
        SecurityChecker.isDebuggerAttached()
        SecurityChecker.isDebugBuild()
    }
}
