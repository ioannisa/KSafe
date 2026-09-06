package eu.anifantakis.lib.ksafe

/** What to do when a security violation is detected. */
enum class SecurityAction {
    /** Skip the check; its probe never runs. */
    IGNORE,

    /** Continue, but invoke [KSafeSecurityPolicy.onViolation]. */
    WARN,

    /** Invoke [KSafeSecurityPolicy.onViolation], then throw [SecurityViolationException]. */
    BLOCK
}

/** Threats KSafe can detect; Web detects none, so every check is a no-op there. */
enum class SecurityViolation {
    /** Rooted (Android) or jailbroken (iOS); not detected on JVM. */
    RootedDevice,

    /** Debugger on the process: Android, Apple, or a JVM started with JDWP flags. */
    DebuggerAttached,

    /** Android debuggable flag, Xcode/simulator environment on Apple, assertions (`-ea`) on JVM. */
    DebugBuild,

    /** Android emulator or iOS simulator; not detected on JVM. */
    Emulator
}

/** Thrown when a violation is detected and its action is [SecurityAction.BLOCK]. */
class SecurityViolationException(
    val violation: SecurityViolation
) : RuntimeException("Security violation: ${violation.name}")

/**
 * Detection and handling of rooted devices, debuggers, debug builds and emulators. The checks run
 * once, inside the `KSafe(...)` factory call; a BLOCK match makes that call throw. Every action
 * defaults to [SecurityAction.IGNORE].
 *
 * @property onViolation Called for each detected violation under WARN or BLOCK, before BLOCK throws.
 */
data class KSafeSecurityPolicy(
    val rootedDevice: SecurityAction = SecurityAction.IGNORE,
    val debuggerAttached: SecurityAction = SecurityAction.IGNORE,
    val debugBuild: SecurityAction = SecurityAction.IGNORE,
    val emulator: SecurityAction = SecurityAction.IGNORE,
    val onViolation: ((SecurityViolation) -> Unit)? = null
) {
    companion object {
        /** Every check [SecurityAction.IGNORE]. */
        val Default = KSafeSecurityPolicy()

        /** Blocks on rooted devices and debuggers; warns on debug build / emulator. */
        val Strict = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.BLOCK,
            debuggerAttached = SecurityAction.BLOCK,
            debugBuild = SecurityAction.WARN,
            emulator = SecurityAction.WARN
        )

        /** Warns on every check but never blocks. */
        val WarnOnly = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.WARN,
            debuggerAttached = SecurityAction.WARN,
            debugBuild = SecurityAction.WARN,
            emulator = SecurityAction.WARN
        )
    }
}
