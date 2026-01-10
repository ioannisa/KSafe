package eu.anifantakis.lib.ksafe

import java.lang.management.ManagementFactory

/**
 * JVM-specific security checker implementation.
 * Note: Root detection and emulator detection are not applicable on JVM.
 */
internal actual object SecurityChecker {

    /**
     * Check if the device is rooted.
     * Not applicable on JVM - always returns false.
     */
    actual fun isDeviceRooted(): Boolean = false

    /**
     * Check if a debugger is attached.
     * Uses JVM management APIs to detect debugging.
     */
    actual fun isDebuggerAttached(): Boolean {
        return try {
            // Check for debug agent in JVM arguments
            val runtimeMxBean = ManagementFactory.getRuntimeMXBean()
            val inputArguments = runtimeMxBean.inputArguments

            inputArguments.any { arg ->
                arg.contains("-agentlib:jdwp") ||
                        arg.contains("-Xdebug") ||
                        arg.contains("-Xrunjdwp")
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check if this is a debug build.
     * On JVM, we check for assertions being enabled.
     */
    actual fun isDebugBuild(): Boolean {
        return try {
            // Check if assertions are enabled (typically only in debug)
            var assertionsEnabled = false
            @Suppress("KotlinConstantConditions", "UNUSED_VALUE")
            assert(true.also { assertionsEnabled = true })
            assertionsEnabled
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check if running on an emulator.
     * Not applicable on JVM - always returns false.
     */
    actual fun isEmulator(): Boolean = false
}
