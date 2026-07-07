package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: SecurityAction/SecurityViolation enums, SecurityViolationException, and KSafeSecurityPolicy presets and data-class behavior.
 */
class KSafeSecurityPolicyTest {

    @Test
    fun securityAction_hasCorrectValues() {
        val actions = SecurityAction.entries
        assertEquals(3, actions.size)
        assertTrue(actions.contains(SecurityAction.IGNORE))
        assertTrue(actions.contains(SecurityAction.WARN))
        assertTrue(actions.contains(SecurityAction.BLOCK))
    }

    @Test
    fun securityAction_ordinalOrder() {
        assertEquals(0, SecurityAction.IGNORE.ordinal)
        assertEquals(1, SecurityAction.WARN.ordinal)
        assertEquals(2, SecurityAction.BLOCK.ordinal)
    }

    @Test
    fun securityViolation_hasCorrectValues() {
        val violations = SecurityViolation.entries
        assertEquals(4, violations.size)
        assertTrue(violations.contains(SecurityViolation.RootedDevice))
        assertTrue(violations.contains(SecurityViolation.DebuggerAttached))
        assertTrue(violations.contains(SecurityViolation.DebugBuild))
        assertTrue(violations.contains(SecurityViolation.Emulator))
    }

    @Test
    fun securityViolationException_containsViolation() {
        val violation = SecurityViolation.RootedDevice
        val exception = SecurityViolationException(violation)

        assertEquals(violation, exception.violation)
        assertTrue(exception.message!!.contains("RootedDevice"))
    }

    @Test
    fun securityViolationException_messageFormat() {
        val exception = SecurityViolationException(SecurityViolation.DebuggerAttached)
        assertEquals("Security violation: DebuggerAttached", exception.message)
    }

    @Test
    fun securityViolationException_canBeCaughtAsRuntimeException() {
        var caught = false
        try {
            throw SecurityViolationException(SecurityViolation.Emulator)
        } catch (e: RuntimeException) {
            caught = true
        }
        assertTrue(caught, "SecurityViolationException should be catchable as RuntimeException")
    }

    @Test
    fun securityPolicy_defaultValues() {
        val policy = KSafeSecurityPolicy()

        assertEquals(SecurityAction.IGNORE, policy.rootedDevice)
        assertEquals(SecurityAction.IGNORE, policy.debuggerAttached)
        assertEquals(SecurityAction.IGNORE, policy.debugBuild)
        assertEquals(SecurityAction.IGNORE, policy.emulator)
        assertNull(policy.onViolation)
    }

    @Test
    fun securityPolicy_defaultPreset_matchesDefaultConstructor() {
        val default = KSafeSecurityPolicy.Default
        val constructor = KSafeSecurityPolicy()

        assertEquals(constructor.rootedDevice, default.rootedDevice)
        assertEquals(constructor.debuggerAttached, default.debuggerAttached)
        assertEquals(constructor.debugBuild, default.debugBuild)
        assertEquals(constructor.emulator, default.emulator)
    }

    @Test
    fun securityPolicy_strictPreset_hasCorrectValues() {
        val strict = KSafeSecurityPolicy.Strict

        assertEquals(SecurityAction.BLOCK, strict.rootedDevice)
        assertEquals(SecurityAction.BLOCK, strict.debuggerAttached)
        assertEquals(SecurityAction.WARN, strict.debugBuild)
        assertEquals(SecurityAction.WARN, strict.emulator)
    }

    @Test
    fun securityPolicy_warnOnlyPreset_hasCorrectValues() {
        val warnOnly = KSafeSecurityPolicy.WarnOnly

        assertEquals(SecurityAction.WARN, warnOnly.rootedDevice)
        assertEquals(SecurityAction.WARN, warnOnly.debuggerAttached)
        assertEquals(SecurityAction.WARN, warnOnly.debugBuild)
        assertEquals(SecurityAction.WARN, warnOnly.emulator)
    }

    @Test
    fun securityPolicy_customConfiguration() {
        val policy = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.BLOCK,
            debuggerAttached = SecurityAction.WARN,
            debugBuild = SecurityAction.IGNORE,
            emulator = SecurityAction.BLOCK
        )

        assertEquals(SecurityAction.BLOCK, policy.rootedDevice)
        assertEquals(SecurityAction.WARN, policy.debuggerAttached)
        assertEquals(SecurityAction.IGNORE, policy.debugBuild)
        assertEquals(SecurityAction.BLOCK, policy.emulator)
    }

    @Test
    fun securityPolicy_withCallback() {
        var callbackInvoked = false
        var receivedViolation: SecurityViolation? = null

        val policy = KSafeSecurityPolicy(
            onViolation = { violation ->
                callbackInvoked = true
                receivedViolation = violation
            }
        )

        assertNotNull(policy.onViolation)

        policy.onViolation.invoke(SecurityViolation.RootedDevice)

        assertTrue(callbackInvoked)
        assertEquals(SecurityViolation.RootedDevice, receivedViolation)
    }

    @Test
    fun securityPolicy_callbackReceivesAllViolationTypes() {
        val receivedViolations = mutableListOf<SecurityViolation>()

        val policy = KSafeSecurityPolicy(
            onViolation = { violation ->
                receivedViolations.add(violation)
            }
        )

        policy.onViolation?.invoke(SecurityViolation.RootedDevice)
        policy.onViolation?.invoke(SecurityViolation.DebuggerAttached)
        policy.onViolation?.invoke(SecurityViolation.DebugBuild)
        policy.onViolation?.invoke(SecurityViolation.Emulator)

        assertEquals(4, receivedViolations.size)
        assertTrue(receivedViolations.contains(SecurityViolation.RootedDevice))
        assertTrue(receivedViolations.contains(SecurityViolation.DebuggerAttached))
        assertTrue(receivedViolations.contains(SecurityViolation.DebugBuild))
        assertTrue(receivedViolations.contains(SecurityViolation.Emulator))
    }

    @Test
    fun securityPolicy_equality() {
        val policy1 = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.WARN,
            debuggerAttached = SecurityAction.BLOCK
        )
        val policy2 = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.WARN,
            debuggerAttached = SecurityAction.BLOCK
        )
        val policy3 = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.BLOCK,
            debuggerAttached = SecurityAction.BLOCK
        )

        assertEquals(policy1, policy2)
        assertFalse(policy1 == policy3)
    }

    @Test
    fun securityPolicy_copy() {
        val original = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.WARN,
            debuggerAttached = SecurityAction.IGNORE
        )
        val copied = original.copy(debuggerAttached = SecurityAction.BLOCK)

        assertEquals(SecurityAction.WARN, original.rootedDevice)
        assertEquals(SecurityAction.IGNORE, original.debuggerAttached)

        assertEquals(SecurityAction.WARN, copied.rootedDevice)
        assertEquals(SecurityAction.BLOCK, copied.debuggerAttached)
    }

    @Test
    fun securityPolicy_hashCode() {
        val policy1 = KSafeSecurityPolicy(rootedDevice = SecurityAction.WARN)
        val policy2 = KSafeSecurityPolicy(rootedDevice = SecurityAction.WARN)

        assertEquals(policy1.hashCode(), policy2.hashCode())
    }

    @Test
    fun securityPolicy_presetsAreSingletons() {
        assertTrue(KSafeSecurityPolicy.Default === KSafeSecurityPolicy.Default)
        assertTrue(KSafeSecurityPolicy.Strict === KSafeSecurityPolicy.Strict)
        assertTrue(KSafeSecurityPolicy.WarnOnly === KSafeSecurityPolicy.WarnOnly)
    }

    @Test
    fun securityPolicy_partialConfiguration_otherFieldsRemainDefault() {
        val policy = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.BLOCK
        )

        assertEquals(SecurityAction.BLOCK, policy.rootedDevice)
        assertEquals(SecurityAction.IGNORE, policy.debuggerAttached)
        assertEquals(SecurityAction.IGNORE, policy.debugBuild)
        assertEquals(SecurityAction.IGNORE, policy.emulator)
    }
}
