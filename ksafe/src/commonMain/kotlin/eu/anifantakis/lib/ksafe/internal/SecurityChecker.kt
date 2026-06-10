package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeSecurityPolicy
import eu.anifantakis.lib.ksafe.SecurityAction
import eu.anifantakis.lib.ksafe.SecurityViolation
import eu.anifantakis.lib.ksafe.SecurityViolationException

/**
 * Platform-specific security checker.
 * Detects rooted/jailbroken devices, debuggers, emulators, and debug builds.
 */
internal expect object SecurityChecker {
    /**
     * Check if the device is rooted (Android) or jailbroken (iOS).
     */
    fun isDeviceRooted(): Boolean

    /**
     * Check if a debugger is attached to the process.
     */
    fun isDebuggerAttached(): Boolean

    /**
     * Check if this is a debug build.
     */
    fun isDebugBuild(): Boolean

    /**
     * Check if running on an emulator/simulator.
     */
    fun isEmulator(): Boolean
}

/**
 * Validates the security policy and handles violations.
 * Called during KSafe initialization.
 *
 * @throws SecurityViolationException if any check fails with BLOCK action.
 */
internal fun validateSecurityPolicy(policy: KSafeSecurityPolicy) {
    val violations = mutableListOf<Pair<SecurityViolation, SecurityAction>>()

    if (policy.rootedDevice != SecurityAction.IGNORE && SecurityChecker.isDeviceRooted()) {
        violations.add(SecurityViolation.RootedDevice to policy.rootedDevice)
    }

    if (policy.debuggerAttached != SecurityAction.IGNORE && SecurityChecker.isDebuggerAttached()) {
        violations.add(SecurityViolation.DebuggerAttached to policy.debuggerAttached)
    }

    if (policy.debugBuild != SecurityAction.IGNORE && SecurityChecker.isDebugBuild()) {
        violations.add(SecurityViolation.DebugBuild to policy.debugBuild)
    }

    if (policy.emulator != SecurityAction.IGNORE && SecurityChecker.isEmulator()) {
        violations.add(SecurityViolation.Emulator to policy.emulator)
    }

    var shouldBlock = false
    var firstBlockingViolation: SecurityViolation? = null

    for ((violation, action) in violations) {
        // Callback fires for every violation, including non-blocking ones
        policy.onViolation?.invoke(violation)

        if (action == SecurityAction.BLOCK) {
            shouldBlock = true
            if (firstBlockingViolation == null) {
                firstBlockingViolation = violation
            }
        }
    }

    if (shouldBlock && firstBlockingViolation != null) {
        throw SecurityViolationException(firstBlockingViolation)
    }
}
