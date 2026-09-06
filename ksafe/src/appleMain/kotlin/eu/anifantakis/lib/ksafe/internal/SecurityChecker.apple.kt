package eu.anifantakis.lib.ksafe.internal

import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.OsFamily
import kotlin.native.Platform
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.set
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.value
import platform.Foundation.NSFileManager
import platform.Foundation.NSProcessInfo
import platform.Foundation.NSSelectorFromString
import platform.Foundation.iOSAppOnMac
import platform.darwin.CTL_KERN
import platform.darwin.KERN_PROC
import platform.darwin.KERN_PROC_PID
import platform.darwin.P_TRACED
import platform.darwin.kinfo_proc
import platform.darwin.sysctl
import platform.posix.getpid
import platform.posix.size_tVar

/** Apple-platform security checker; the jailbreak probes match on every Mac, hence the short-circuits. */
internal actual object SecurityChecker {

    @OptIn(ExperimentalNativeApi::class)
    private val isMacOs: Boolean = Platform.osFamily == OsFamily.MACOSX

    /** An iOS binary on an Apple Silicon Mac: the probes match the real macOS filesystem while [isMacOs]
     *  is false. `isiOSAppOnMac` only exists from iOS 14, hence the selector guard. */
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
        "/usr/bin/ssh",
        // Rootless jailbreaks (palera1n, Dopamine) install under /var/jb, so the probes above miss them.
        "/var/jb",
        "/var/jb/Applications/Sileo.app",
        "/var/jb/usr/bin/apt",
        "/var/jb/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/var/binpack"
    )

    /** Always `false` on macOS, where the iOS probes fire on every Mac and would block the library. */
    actual fun isDeviceRooted(): Boolean {
        if (isMacOs) return false
        if (isIosAppOnMac) return false
        if (isEmulator()) return false

        return checkJailbreakPaths() || checkWritableSystemPaths()
    }

    /** `P_TRACED` via `sysctl`, OR-ed with env vars that also catch dylib injection. */
    actual fun isDebuggerAttached(): Boolean = try {
        val env = NSProcessInfo.processInfo.environment
        isProcessTraced() ||
                env["_"] as? String == "lldb" ||
                env.containsKey("DYLD_INSERT_LIBRARIES")
    } catch (_: Throwable) {
        // Fail-open: a security probe must not crash KSafe(...) construction.
        false
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun isProcessTraced(): Boolean = try {
        memScoped {
            val mib = allocArray<IntVar>(4)
            mib[0] = CTL_KERN
            mib[1] = KERN_PROC
            mib[2] = KERN_PROC_PID
            mib[3] = getpid()
            val info = alloc<kinfo_proc>()
            val size = alloc<size_tVar>()
            size.value = sizeOf<kinfo_proc>().convert()
            sysctl(mib, 4u, info.ptr, size.ptr, null, 0u) == 0 &&
                    (info.kp_proc.p_flag and P_TRACED) != 0
        }
    } catch (_: Throwable) {
        false
    }

    /** iOS has no FLAG_DEBUGGABLE equivalent, so this combines env, simulator and debugger heuristics. */
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
