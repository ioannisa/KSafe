package eu.anifantakis.lib.ksafe.internal

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
     *
     * Catches `Throwable` (not just `Exception`) so a missing
     * `java.management` JDK module — common in trimmed jlink runtimes such
     * as Compose Desktop release distributables, see
     * `docs/JVM_PROTECTION.md` — surfaces as "no debugger detected" rather
     * than crashing `KSafe(...)` construction with `NoClassDefFoundError`.
     * The honest answer there is "unknown," but production apps shouldn't
     * fail to start over a security probe.
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
        } catch (_: Throwable) {
            // `NoClassDefFoundError` (missing `java.management` in a trimmed
            // jlink runtime) or any other failure → can't tell, fail open.
            false
        }
    }

    /**
     * Check if this is a debug build.
     * On JVM, we check for assertions being enabled.
     *
     * Catches `Throwable` for the same reason as [isDebuggerAttached] —
     * defensive against trimmed runtimes and JVM oddities.
     */
    actual fun isDebugBuild(): Boolean {
        return try {
            // Check if assertions are enabled (typically only in debug)
            var assertionsEnabled = false
            @Suppress("KotlinConstantConditions", "UNUSED_VALUE")
            assert(true.also { assertionsEnabled = true })
            assertionsEnabled
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Check if running on an emulator.
     * Not applicable on JVM - always returns false.
     */
    actual fun isEmulator(): Boolean = false
}
