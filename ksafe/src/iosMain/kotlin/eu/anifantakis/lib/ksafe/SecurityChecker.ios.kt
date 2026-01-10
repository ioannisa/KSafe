package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSProcessInfo

/**
 * iOS-specific security checker implementation.
 */
internal actual object SecurityChecker {

    // Common jailbreak paths to check
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

    /**
     * Check if the device is jailbroken.
     * Uses multiple detection methods for better accuracy.
     */
    actual fun isDeviceRooted(): Boolean {
        // Don't check on simulator - it's expected to have different paths
        if (isEmulator()) return false

        return checkJailbreakPaths() || checkWritableSystemPaths()
    }

    /**
     * Check if a debugger is attached.
     * Note: Full sysctl-based detection requires complex C interop.
     * This is a simplified check using environment variables.
     */
    actual fun isDebuggerAttached(): Boolean {
        // Check for common debugger environment variables
        val env = NSProcessInfo.processInfo.environment
        return env["_"] as? String == "lldb" ||
                env.containsKey("DYLD_INSERT_LIBRARIES")
    }

    /**
     * Check if this is a debug build.
     * On iOS, we use multiple heuristics since there's no direct equivalent
     * to Android's FLAG_DEBUGGABLE:
     * - Check for Xcode debugging environment variables
     * - Check for memory debugging tools
     * - Check if running with debugger (implies debug session)
     * - Check for Xcode-specific build paths
     */
    actual fun isDebugBuild(): Boolean {
        val env = NSProcessInfo.processInfo.environment

        // Memory debugging tools (explicitly enabled in Xcode scheme)
        val hasMemoryDebugging = env.containsKey("NSZombieEnabled") ||
                env.containsKey("MallocStackLogging") ||
                env.containsKey("MallocGuardEdges") ||
                env.containsKey("MallocScribble")

        // Xcode-specific environment variables set during debug sessions
        val hasXcodeDebugVars = env.containsKey("__XCODE_BUILT_PRODUCTS_DIR_PATHS") ||
                env.containsKey("XCODE_RUNNING_FOR_PREVIEWS") ||
                env.containsKey("__XPC_DYLD_LIBRARY_PATH") ||
                env.containsKey("DYLD_FRAMEWORK_PATH") ||
                env.containsKey("DYLD_LIBRARY_PATH")

        // Running on simulator is typically debug
        val isSimulator = isEmulator()

        // If debugger is attached, it's almost certainly a debug session
        val hasDebugger = isDebuggerAttached()

        return hasMemoryDebugging || hasXcodeDebugVars || isSimulator || hasDebugger
    }

    /**
     * Check if running on iOS Simulator.
     */
    actual fun isEmulator(): Boolean {
        val env = NSProcessInfo.processInfo.environment
        // SIMULATOR_MODEL_IDENTIFIER is set when running on simulator
        return env["SIMULATOR_MODEL_IDENTIFIER"] != null ||
                env["SIMULATOR_DEVICE_NAME"] != null
    }

    // --- Private helper methods ---

    private fun checkJailbreakPaths(): Boolean {
        val fileManager = NSFileManager.defaultManager
        return jailbreakPaths.any { path ->
            fileManager.fileExistsAtPath(path)
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun checkWritableSystemPaths(): Boolean {
        // Try to write to a system path - should fail on non-jailbroken devices
        val testPath = "/private/jailbreak_test.txt"

        return try {
            val fileManager = NSFileManager.defaultManager

            // Try to create a file in /private (should fail on non-jailbroken)
            val success = fileManager.createFileAtPath(testPath, null, null)
            if (success) {
                // Clean up and return true - this is a jailbroken device
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
