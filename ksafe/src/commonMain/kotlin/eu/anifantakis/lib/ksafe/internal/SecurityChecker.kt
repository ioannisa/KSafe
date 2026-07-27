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

    // `detect` stays a lambda so an IGNOREd check never runs its probe — root and emulator
    // detection touch the filesystem and the PackageManager.
    fun check(action: SecurityAction, violation: SecurityViolation, detect: () -> Boolean) {
        if (action != SecurityAction.IGNORE && detect()) violations.add(violation to action)
    }

    check(policy.rootedDevice, SecurityViolation.RootedDevice, SecurityChecker::isDeviceRooted)
    check(policy.debuggerAttached, SecurityViolation.DebuggerAttached, SecurityChecker::isDebuggerAttached)
    check(policy.debugBuild, SecurityViolation.DebugBuild, SecurityChecker::isDebugBuild)
    check(policy.emulator, SecurityViolation.Emulator, SecurityChecker::isEmulator)

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
