package eu.anifantakis.lib.ksafe

/** Action to take when a security violation is detected. */
enum class SecurityAction {
    /** Ignore the violation and continue normally. */
    IGNORE,

    /** Allow the operation but invoke the [KSafeSecurityPolicy.onViolation] callback. */
    WARN,

    /** Block the operation and throw [SecurityViolationException]. */
    BLOCK
}

/** Types of security violations that can be detected. */
enum class SecurityViolation {
    /** Device is rooted (Android) or jailbroken (iOS). */
    RootedDevice,

    /** A debugger is attached to the process. */
    DebuggerAttached,

    /** App is running a debug build. */
    DebugBuild,

    /** App is running on an emulator/simulator. */
    Emulator
}

/** Thrown when a violation is detected and its action is [SecurityAction.BLOCK]. */
class SecurityViolationException(
    val violation: SecurityViolation
) : RuntimeException("Security violation: ${violation.name}")

/**
 * Security policy for KSafe — detection and handling of threats such as
 * rooted/jailbroken devices, debugger attachment, and emulator usage.
 *
 * All actions default to [SecurityAction.IGNORE] for backwards compatibility.
 *
 * @property onViolation Invoked when a violation is detected under WARN or
 *   BLOCK — before throwing (BLOCK) or continuing (WARN).
 */
data class KSafeSecurityPolicy(
    val rootedDevice: SecurityAction = SecurityAction.IGNORE,
    val debuggerAttached: SecurityAction = SecurityAction.IGNORE,
    val debugBuild: SecurityAction = SecurityAction.IGNORE,
    val emulator: SecurityAction = SecurityAction.IGNORE,
    val onViolation: ((SecurityViolation) -> Unit)? = null
) {
    companion object {
        /** All checks ignored. */
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
