package eu.anifantakis.lib.ksafe

/**
 * Action to take when a security violation is detected.
 */
enum class SecurityAction {
    /**
     * Ignore the violation and continue normally.
     * Use this for development or non-sensitive apps.
     */
    IGNORE,

    /**
     * Allow operation but invoke the [KSafeSecurityPolicy.onViolation] callback.
     * Use this to show warnings to users or log security events.
     */
    WARN,

    /**
     * Block the operation and throw [SecurityViolationException].
     * Use this for high-security apps (banking, enterprise).
     */
    BLOCK
}

/**
 * Types of security violations that can be detected.
 */
enum class SecurityViolation {
    /**
     * Device is rooted (Android) or jailbroken (iOS).
     * This allows apps to bypass sandboxing and access other apps' data.
     */
    RootedDevice,

    /**
     * A debugger is attached to the process.
     * This allows inspection of memory and runtime values.
     */
    DebuggerAttached,

    /**
     * App is running in debug mode (debug build).
     * Debug builds may have weaker security settings.
     */
    DebugBuild,

    /**
     * App is running on an emulator/simulator.
     * Emulators have weaker security guarantees.
     */
    Emulator
}

/**
 * Exception thrown when a security violation is detected and action is [SecurityAction.BLOCK].
 */
class SecurityViolationException(
    val violation: SecurityViolation
) : RuntimeException("Security violation: ${violation.name}")

/**
 * Security policy configuration for KSafe.
 *
 * Allows detection and handling of potential security threats such as
 * rooted/jailbroken devices, debugger attachment, and emulator usage.
 *
 * ## Example
 * ```kotlin
 * val ksafe = KSafe(
 *     context = context,
 *     securityPolicy = KSafeSecurityPolicy(
 *         rootedDevice = SecurityAction.WARN,
 *         debuggerAttached = SecurityAction.BLOCK,
 *         onViolation = { violation ->
 *             analytics.logSecurityEvent(violation.name)
 *         }
 *     )
 * )
 * ```
 *
 * ## Default Behavior
 * By default, all actions are set to [SecurityAction.IGNORE] for backwards
 * compatibility and to avoid breaking existing apps.
 *
 * ## Platform Support
 * | Check | Android | iOS | JVM |
 * |-------|---------|-----|-----|
 * | Rooted/Jailbroken | ✅ | ✅ | ❌ N/A |
 * | Debugger Attached | ✅ | ✅ | ✅ |
 * | Debug Build | ✅ | ✅ | ✅ |
 * | Emulator | ✅ | ✅ | ❌ N/A |
 *
 * @property rootedDevice Action for rooted (Android) or jailbroken (iOS) devices.
 * @property debuggerAttached Action when a debugger is attached to the process.
 * @property debugBuild Action when running a debug build.
 * @property emulator Action when running on emulator/simulator.
 * @property onViolation Callback invoked when a violation is detected and action is WARN or BLOCK.
 *                       Called before throwing exception (for BLOCK) or continuing (for WARN).
 */
data class KSafeSecurityPolicy(
    val rootedDevice: SecurityAction = SecurityAction.IGNORE,
    val debuggerAttached: SecurityAction = SecurityAction.IGNORE,
    val debugBuild: SecurityAction = SecurityAction.IGNORE,
    val emulator: SecurityAction = SecurityAction.IGNORE,
    val onViolation: ((SecurityViolation) -> Unit)? = null
) {
    companion object {
        /**
         * Default policy - all checks ignored.
         * Safe for development and non-sensitive apps.
         */
        val Default = KSafeSecurityPolicy()

        /**
         * Strict policy - blocks on rooted devices and debuggers.
         * Recommended for banking, enterprise, and high-security apps.
         */
        val Strict = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.BLOCK,
            debuggerAttached = SecurityAction.BLOCK,
            debugBuild = SecurityAction.WARN,
            emulator = SecurityAction.WARN
        )

        /**
         * Warn-only policy - warns but doesn't block.
         * Good for logging security events without breaking UX.
         */
        val WarnOnly = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.WARN,
            debuggerAttached = SecurityAction.WARN,
            debugBuild = SecurityAction.WARN,
            emulator = SecurityAction.WARN
        )
    }
}
