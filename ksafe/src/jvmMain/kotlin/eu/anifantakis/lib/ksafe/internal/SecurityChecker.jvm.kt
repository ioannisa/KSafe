package eu.anifantakis.lib.ksafe.internal

import java.lang.management.ManagementFactory

/** Root and emulator detection are not applicable on JVM. */
internal actual object SecurityChecker {

    actual fun isDeviceRooted(): Boolean = false

    /**
     * Reports whether a debugger is attached, from the JVM input arguments.
     *
     * Catches `Throwable`: a trimmed jlink runtime may lack `java.management`,
     * and the resulting `NoClassDefFoundError` must read as "no debugger"
     * rather than crash `KSafe(...)` construction.
     */
    actual fun isDebuggerAttached(): Boolean {
        return try {
            val runtimeMxBean = ManagementFactory.getRuntimeMXBean()
            val inputArguments = runtimeMxBean.inputArguments

            inputArguments.any { arg ->
                arg.contains("-agentlib:jdwp") ||
                        arg.contains("-Xdebug") ||
                        arg.contains("-Xrunjdwp")
            }
        } catch (_: Throwable) {
            false
        }
    }

    /** Approximates a debug build by whether assertions are enabled. */
    actual fun isDebugBuild(): Boolean {
        return try {
            var assertionsEnabled = false
            @Suppress("KotlinConstantConditions", "UNUSED_VALUE")
            assert(true.also { assertionsEnabled = true })
            assertionsEnabled
        } catch (_: Throwable) {
            false
        }
    }

    actual fun isEmulator(): Boolean = false
}
