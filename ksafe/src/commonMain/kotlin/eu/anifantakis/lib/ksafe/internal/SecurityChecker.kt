package eu.anifantakis.lib.ksafe.internal

import eu.anifantakis.lib.ksafe.KSafeSecurityPolicy
import eu.anifantakis.lib.ksafe.SecurityAction
import eu.anifantakis.lib.ksafe.SecurityViolation
import eu.anifantakis.lib.ksafe.SecurityViolationException

/** Platform detection of rooted/jailbroken devices, debuggers, emulators, and debug builds. */
internal expect object SecurityChecker {
    fun isDeviceRooted(): Boolean
    fun isDebuggerAttached(): Boolean
    fun isDebugBuild(): Boolean
    fun isEmulator(): Boolean
}

/**
 * Validates [policy] at KSafe initialization; throws [SecurityViolationException]
 * for the first violation whose action is BLOCK.
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
