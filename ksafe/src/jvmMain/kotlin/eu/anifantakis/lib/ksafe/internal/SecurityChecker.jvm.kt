package eu.anifantakis.lib.ksafe.internal

import java.lang.management.ManagementFactory

/** Root and emulator detection are not applicable on JVM. */
internal actual object SecurityChecker {

    actual fun isDeviceRooted(): Boolean = false

    /** Catches `Throwable`: a trimmed jlink runtime may lack `java.management`, and that must read
     *  as "no debugger" rather than fail construction. */
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

    /** Approximated by whether the JVM enables assertions (`-ea`) for this class. */
    actual fun isDebugBuild(): Boolean = try {
        SecurityChecker::class.java.desiredAssertionStatus()
    } catch (_: Throwable) {
        false
    }

    actual fun isEmulator(): Boolean = false
}
