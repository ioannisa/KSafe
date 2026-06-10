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
     * Check if a debugger is attached by inspecting JVM input arguments.
     *
     * Catches `Throwable` (not just `Exception`): trimmed jlink runtimes
     * (e.g. Compose Desktop release distributables) may lack the
     * `java.management` module, and the resulting `NoClassDefFoundError`
     * must surface as "no debugger detected" rather than crashing
     * `KSafe(...)` construction.
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
            // Can't tell (e.g. missing java.management) — fail open.
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
