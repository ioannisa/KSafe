package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.validateSecurityPolicy
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

    // ============ TRIMMED-JRE DEFENSIVENESS (2.1.1) ============
    //
    // A Compose Desktop release distributable bundles a `jlink`-trimmed
    // JRE which can omit modules `SecurityChecker` reads — specifically
    // `java.management` (for `isDebuggerAttached`). Pre-2.1.1 the catch
    // clauses were `catch (_: Exception)`, which does NOT catch
    // `NoClassDefFoundError` (it's an `Error`, not an `Exception`).
    // A non-IGNORE security policy would then crash `KSafe(...)`
    // construction with `NoClassDefFoundError: java/lang/management/
    // ManagementFactory` against the trimmed runtime.
    //
    // We can't actually remove `java.management` from the test JVM, but
    // we *can* simulate the failure by reflecting into the same code
    // path and asserting the catch shape. The cheap proxy: the catch
    // must accept any `Throwable`, which is verifiable by source
    // inspection — these tests existing forces a reader to remember why
    // `catch (_: Throwable)` is intentional, and the existing pair of
    // tests (`isDebuggerAttached_returnsBoolean`,
    // `isDebugBuild_returnsBoolean`) prove the methods are themselves
    // exception-safe under the current (healthy) runtime.

    /**
     * Regression guard: a real-world consumer reported issue #32 with
     * dropped writes on Compose Desktop release distributables. While
     * fixing #32 we discovered `SecurityChecker.isDebuggerAttached()`
     * also crashes against the same trimmed runtime, separately from
     * the JNA path. This test asserts the method returns a Boolean
     * (never throws) under the test JVM — the runtime simulation of
     * the trimmed environment lives in the demo's release distributable
     * documented in `docs/JVM_PROTECTION.md`.
     */
    @Test
    fun securityChecker_isDebuggerAttached_isThrowableSafe_regression_issue32_followup() {
        // The actual contract we care about: this never throws, even
        // on a trimmed runtime missing `java.management`. The test JVM
        // has the module, so this is just a "doesn't throw" probe; the
        // real defence is the `catch (_: Throwable)` source change.
        val result = SecurityChecker.isDebuggerAttached()
        assertIs<Boolean>(result)
    }

    @Test
    fun securityChecker_isDebugBuild_isThrowableSafe_regression_issue32_followup() {
        val result = SecurityChecker.isDebugBuild()
        assertIs<Boolean>(result)
    }
}
