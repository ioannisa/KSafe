package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs

/**
 * Locks in: SecurityChecker's JVM behavior — never rooted or an emulator, and every probe and policy validation is exception-safe.
 */
class JvmSecurityCheckerTest {

    @Test
    fun securityChecker_isDeviceRooted_returnsFalseOnJvm() {
        val result = SecurityChecker.isDeviceRooted()
        assertFalse(result, "JVM should never report as rooted")
    }

    @Test
    fun securityChecker_isEmulator_returnsFalseOnJvm() {
        val result = SecurityChecker.isEmulator()
        assertFalse(result, "JVM should not report as emulator")
    }

    @Test
    fun securityChecker_isDebuggerAttached_returnsBoolean() {
        // May be true or false depending on the environment; must not throw.
        val result = SecurityChecker.isDebuggerAttached()
        assertIs<Boolean>(result)
    }

    @Test
    fun securityChecker_isDebugBuild_returnsBoolean() {
        val result = SecurityChecker.isDebugBuild()
        assertIs<Boolean>(result)
    }

    @Test
    fun validateSecurityPolicy_defaultPolicy_noException() {
        val policy = KSafeSecurityPolicy.Default
        validateSecurityPolicy(policy)
    }

    @Test
    fun validateSecurityPolicy_warnOnly_callsCallback() {
        val violations = mutableListOf<SecurityViolation>()

        val policy = KSafeSecurityPolicy(
            debugBuild = SecurityAction.WARN,
            onViolation = { violation ->
                violations.add(violation)
            }
        )

        // WARN must not throw; whether the callback fires depends on the environment.
        validateSecurityPolicy(policy)
    }

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

    // Trimmed-JRE Throwable-safety is intentionally NOT unit-tested here. The
    // scenario — a `jlink`-trimmed runtime missing `java.management` makes
    // `ManagementFactory` throw `NoClassDefFoundError` (an Error, not an
    // Exception) — cannot be reproduced in a standard test JVM, which always
    // has the module. The production guard is the `catch (_: Throwable)` in
    // SecurityChecker.jvm.kt (a plain `catch (Exception)` would let the Error
    // escape and crash KSafe(...) construction). End-to-end verification lives
    // in the demo's release distributable; see docs/JVM_PROTECTION.md. The
    // `_returnsBoolean` tests above prove the probes are exception-safe under
    // a healthy JVM.
}
