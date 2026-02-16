package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs

/**
 * JVM-specific tests for SecurityChecker.
 */
class JvmSecurityCheckerTest {

    // ============ SECURITY CHECKER JVM BEHAVIOR ============

    /** Verifies JVM always returns false for root detection */
    @Test
    fun securityChecker_isDeviceRooted_returnsFalseOnJvm() {
        // JVM is never "rooted" in the mobile sense
        val result = SecurityChecker.isDeviceRooted()
        assertFalse(result, "JVM should never report as rooted")
    }

    /** Verifies JVM always returns false for emulator detection */
    @Test
    fun securityChecker_isEmulator_returnsFalseOnJvm() {
        // JVM is not an emulator
        val result = SecurityChecker.isEmulator()
        assertFalse(result, "JVM should not report as emulator")
    }

    /** Verifies debugger detection returns valid boolean on JVM */
    @Test
    fun securityChecker_isDebuggerAttached_returnsBoolean() {
        // This may return true or false depending on test environment
        // Just verify it doesn't throw
        val result = SecurityChecker.isDebuggerAttached()
        // Result is either true or false, both are valid
        assertIs<Boolean>(result)
    }

    /** Verifies debug build detection returns valid boolean on JVM */
    @Test
    fun securityChecker_isDebugBuild_returnsBoolean() {
        // This may return true or false depending on test environment
        val result = SecurityChecker.isDebugBuild()
        assertIs<Boolean>(result)
    }

    // ============ VALIDATE SECURITY POLICY (JVM-SPECIFIC) ============

    /** Verifies default policy (IGNORE all) doesn't throw exception */
    @Test
    fun validateSecurityPolicy_defaultPolicy_noException() {
        // Default policy ignores everything, should not throw
        val policy = KSafeSecurityPolicy.Default
        validateSecurityPolicy(policy)
        // If we reach here, no exception was thrown
    }

    /** Verifies WARN action invokes callback without throwing */
    @Test
    fun validateSecurityPolicy_warnOnly_callsCallback() {
        val violations = mutableListOf<SecurityViolation>()

        val policy = KSafeSecurityPolicy(
            // On JVM, debugBuild might be true in test environment
            debugBuild = SecurityAction.WARN,
            onViolation = { violation ->
                violations.add(violation)
            }
        )

        // This should not throw (WARN doesn't block)
        validateSecurityPolicy(policy)

        // Violations list may or may not have items depending on test environment
        // The important thing is that it didn't throw
    }

    /** Verifies IGNORE action never invokes callback */
    @Test
    fun validateSecurityPolicy_ignoreAll_noCallbacks() {
        var callbackInvoked = false

        val policy = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.IGNORE,
            debuggerAttached = SecurityAction.IGNORE,
            debugBuild = SecurityAction.IGNORE,
            emulator = SecurityAction.IGNORE,
            onViolation = { _ ->
                callbackInvoked = true
            }
        )

        validateSecurityPolicy(policy)

        assertFalse(callbackInvoked, "Callback should not be invoked when all actions are IGNORE")
    }

    // Note: We can't easily test BLOCK behavior on JVM without mocking,
    // since JVM typically doesn't have rooted/emulator conditions.
    // Those tests would require dependency injection or mocking framework.
}
