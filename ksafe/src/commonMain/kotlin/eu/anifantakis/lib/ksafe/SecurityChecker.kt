package eu.anifantakis.lib.ksafe

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

    // Check rooted/jailbroken
    if (policy.rootedDevice != SecurityAction.IGNORE && SecurityChecker.isDeviceRooted()) {
        violations.add(SecurityViolation.RootedDevice to policy.rootedDevice)
    }

    // Check debugger
    if (policy.debuggerAttached != SecurityAction.IGNORE && SecurityChecker.isDebuggerAttached()) {
        violations.add(SecurityViolation.DebuggerAttached to policy.debuggerAttached)
    }

    // Check debug build
    if (policy.debugBuild != SecurityAction.IGNORE && SecurityChecker.isDebugBuild()) {
        violations.add(SecurityViolation.DebugBuild to policy.debugBuild)
    }

    // Check emulator
    if (policy.emulator != SecurityAction.IGNORE && SecurityChecker.isEmulator()) {
        violations.add(SecurityViolation.Emulator to policy.emulator)
    }

    // Process violations
    var shouldBlock = false
    var firstBlockingViolation: SecurityViolation? = null

    for ((violation, action) in violations) {
        // Always call the callback if provided
        policy.onViolation?.invoke(violation)

        // Mark for blocking if needed
        if (action == SecurityAction.BLOCK) {
            shouldBlock = true
            if (firstBlockingViolation == null) {
                firstBlockingViolation = violation
            }
        }
    }

    // Block if any violation required it
    if (shouldBlock && firstBlockingViolation != null) {
        throw SecurityViolationException(firstBlockingViolation)
    }
}
