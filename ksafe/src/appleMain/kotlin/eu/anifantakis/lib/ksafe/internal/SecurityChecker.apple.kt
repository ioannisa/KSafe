package eu.anifantakis.lib.ksafe.internal

import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.OsFamily
import kotlin.native.Platform
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSSelectorFromString
import platform.Foundation.iOSAppOnMac

/**
 * Apple-platform security checker, shared by iOS and macOS.
 *
 * The jailbreak path probes only make sense on iOS — every Mac has `/bin/sh`, `/usr/bin/ssh`,
 * etc. — so [isDeviceRooted] short-circuits to `false` on macOS (and for an iOS binary on an
 * Apple Silicon Mac, which sees the same filesystem; see [isIosAppOnMac]). Callers wanting
 * stronger macOS guarantees can plug in their own [eu.anifantakis.lib.ksafe.KSafeSecurityPolicy].
 */
internal actual object SecurityChecker {

    @OptIn(ExperimentalNativeApi::class)
    private val isMacOs: Boolean = Platform.osFamily == OsFamily.MACOSX

    /**
     * True when this iOS binary runs on an Apple Silicon Mac ("iOS app on Mac"). There the
     * process sees the real macOS filesystem where the jailbreak probes trivially match, yet
     * [isMacOs] is `false` (`Platform.osFamily` is the compile-time iosArm64 slice) — without
     * this a clean Mac would classify as jailbroken and `KSafeSecurityPolicy.Strict` would
     * throw at construction. The selector guard keeps pre-iOS-14 runtimes safe and the catch
     * keeps the probe from ever crashing `KSafe(...)`.
     */
    @OptIn(ExperimentalForeignApi::class)
    private val isIosAppOnMac: Boolean = try {
        val info = NSProcessInfo.processInfo
        info.respondsToSelector(NSSelectorFromString("isiOSAppOnMac")) && info.iOSAppOnMac
    } catch (_: Throwable) {
        false
    }

    private val jailbreakPaths = listOf(
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/blackra1n.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/usr/sbin/sshd",
        "/bin/bash",
        "/etc/apt",
        "/var/cache/apt",
        "/var/lib/apt",
        "/var/lib/cydia",
        "/bin/sh",
        "/usr/bin/ssh"
    )

    /** True if the device is jailbroken; always `false` on macOS (the iOS heuristics fire on
     *  every Mac and would otherwise block the whole library). */
    actual fun isDeviceRooted(): Boolean {
        if (isMacOs) return false
        // iOS slice on an Apple Silicon Mac: same filesystem, same false positives.
        if (isIosAppOnMac) return false
        // Simulator has different paths; don't check.
        if (isEmulator()) return false

        return checkJailbreakPaths() || checkWritableSystemPaths()
    }

    /** True if a debugger is attached (env-var heuristic; full sysctl detection needs C interop). */
    actual fun isDebuggerAttached(): Boolean = try {
        val env = NSProcessInfo.processInfo.environment
        env["_"] as? String == "lldb" ||
                env.containsKey("DYLD_INSERT_LIBRARIES")
    } catch (_: Throwable) {
        // Fail-open: a security probe must never crash KSafe(...) construction; "unknown" →
        // not-attached is the safe-for-availability answer.
        false
    }

    /**
     * True if this looks like a debug build. iOS has no FLAG_DEBUGGABLE equivalent, so this
     * combines heuristics: memory-debug env vars, Xcode debug env vars, simulator, debugger.
     */
    actual fun isDebugBuild(): Boolean {
        val env = NSProcessInfo.processInfo.environment

        val hasMemoryDebugging = env.containsKey("NSZombieEnabled") ||
                env.containsKey("MallocStackLogging") ||
                env.containsKey("MallocGuardEdges") ||
                env.containsKey("MallocScribble")

        val hasXcodeDebugVars = env.containsKey("__XCODE_BUILT_PRODUCTS_DIR_PATHS") ||
                env.containsKey("XCODE_RUNNING_FOR_PREVIEWS") ||
                env.containsKey("__XPC_DYLD_LIBRARY_PATH") ||
                env.containsKey("DYLD_FRAMEWORK_PATH") ||
                env.containsKey("DYLD_LIBRARY_PATH")

        val isSimulator = isEmulator()
        val hasDebugger = isDebuggerAttached()

        return hasMemoryDebugging || hasXcodeDebugVars || isSimulator || hasDebugger
    }

    /** True if running on the iOS Simulator. */
    actual fun isEmulator(): Boolean {
        val env = NSProcessInfo.processInfo.environment
        return env["SIMULATOR_MODEL_IDENTIFIER"] != null ||
                env["SIMULATOR_DEVICE_NAME"] != null
    }

    private fun checkJailbreakPaths(): Boolean {
        val fileManager = NSFileManager.defaultManager
        return jailbreakPaths.any { path ->
            fileManager.fileExistsAtPath(path)
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun checkWritableSystemPaths(): Boolean {
        // Creating a file under /private succeeds only on a jailbroken device.
        val testPath = "/private/jailbreak_test.txt"

        return try {
            val fileManager = NSFileManager.defaultManager
            val success = fileManager.createFileAtPath(testPath, null, null)
            if (success) {
                fileManager.removeItemAtPath(testPath, null)
                true
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }
}
