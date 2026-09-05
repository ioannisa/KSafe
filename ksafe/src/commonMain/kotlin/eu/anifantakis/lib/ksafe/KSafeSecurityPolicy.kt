package eu.anifantakis.lib.ksafe

/** What to do when a security violation is detected. */
enum class SecurityAction {
    IGNORE,

    /** Continue, but invoke [KSafeSecurityPolicy.onViolation]. */
    WARN,

    /** Throw [SecurityViolationException]. */
    BLOCK
}

/** Threats KSafe can detect. */
enum class SecurityViolation {
    /** Rooted (Android) or jailbroken (iOS). */
    RootedDevice,

    DebuggerAttached,

    DebugBuild,

    Emulator
}

/** Thrown when a violation is detected and its action is [SecurityAction.BLOCK]. */
class SecurityViolationException(
    val violation: SecurityViolation
) : RuntimeException("Security violation: ${violation.name}")

/** Detection and handling of rooted devices, debuggers, debug builds and emulators. Every action
 *  defaults to [SecurityAction.IGNORE]; [onViolation] fires under WARN and BLOCK. */
data class KSafeSecurityPolicy(
    val rootedDevice: SecurityAction = SecurityAction.IGNORE,
    val debuggerAttached: SecurityAction = SecurityAction.IGNORE,
    val debugBuild: SecurityAction = SecurityAction.IGNORE,
    val emulator: SecurityAction = SecurityAction.IGNORE,
    val onViolation: ((SecurityViolation) -> Unit)? = null
) {
    companion object {
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
