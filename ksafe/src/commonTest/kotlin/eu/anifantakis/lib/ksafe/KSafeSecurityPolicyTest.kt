package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tests for [KSafeSecurityPolicy], [SecurityAction], [SecurityViolation], and [SecurityViolationException].
 */
class KSafeSecurityPolicyTest {

    // ============ SECURITY ACTION TESTS ============

    /** Verifies SecurityAction enum contains exactly 3 values: IGNORE, WARN, BLOCK */
    @Test
    fun securityAction_hasCorrectValues() {
        val actions = SecurityAction.entries
        assertEquals(3, actions.size)
        assertTrue(actions.contains(SecurityAction.IGNORE))
        assertTrue(actions.contains(SecurityAction.WARN))
        assertTrue(actions.contains(SecurityAction.BLOCK))
    }

    /** Verifies SecurityAction ordinal values maintain expected order for severity */
    @Test
    fun securityAction_ordinalOrder() {
        // Verify order is IGNORE, WARN, BLOCK
        assertEquals(0, SecurityAction.IGNORE.ordinal)
        assertEquals(1, SecurityAction.WARN.ordinal)
        assertEquals(2, SecurityAction.BLOCK.ordinal)
    }

    // ============ SECURITY VIOLATION TESTS ============

    /** Verifies SecurityViolation enum has correct number of entries */
    @Test
    fun securityViolation_hasCorrectValues() {
        val violations = SecurityViolation.entries
        assertEquals(4, violations.size)
        assertTrue(violations.contains(SecurityViolation.RootedDevice))
        assertTrue(violations.contains(SecurityViolation.DebuggerAttached))
        assertTrue(violations.contains(SecurityViolation.DebugBuild))
        assertTrue(violations.contains(SecurityViolation.Emulator))
    }

    // ============ SECURITY VIOLATION EXCEPTION TESTS ============

    /** Verifies SecurityViolationException stores the violation and includes enum name in message */
    @Test
    fun securityViolationException_containsViolation() {
        val violation = SecurityViolation.RootedDevice
        val exception = SecurityViolationException(violation)

        assertEquals(violation, exception.violation)
        assertTrue(exception.message!!.contains("RootedDevice"))
    }

    /** Verifies exception message follows expected format pattern */
    @Test
    fun securityViolationException_messageFormat() {
        val exception = SecurityViolationException(SecurityViolation.DebuggerAttached)
        assertEquals("Security violation: DebuggerAttached", exception.message)
    }

    /** Verifies exception extends RuntimeException for try-catch compatibility */
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

    // ============ KSAFE SECURITY POLICY - DEFAULT VALUES ============

    /** Verifies default constructor sets all actions to IGNORE with no callback */
    @Test
    fun securityPolicy_defaultValues() {
        val policy = KSafeSecurityPolicy()

        assertEquals(SecurityAction.IGNORE, policy.rootedDevice)
        assertEquals(SecurityAction.IGNORE, policy.debuggerAttached)
        assertEquals(SecurityAction.IGNORE, policy.debugBuild)
        assertEquals(SecurityAction.IGNORE, policy.emulator)
        assertNull(policy.onViolation)
    }

    /** Verifies Default preset matches default constructor behavior */
    @Test
    fun securityPolicy_defaultPreset_matchesDefaultConstructor() {
        val default = KSafeSecurityPolicy.Default
        val constructor = KSafeSecurityPolicy()

        assertEquals(constructor.rootedDevice, default.rootedDevice)
        assertEquals(constructor.debuggerAttached, default.debuggerAttached)
        assertEquals(constructor.debugBuild, default.debugBuild)
        assertEquals(constructor.emulator, default.emulator)
    }

    // ============ KSAFE SECURITY POLICY - PRESET POLICIES ============

    /** Verifies Strict preset blocks root/debugger and warns on debug/emulator */
    @Test
    fun securityPolicy_strictPreset_hasCorrectValues() {
        val strict = KSafeSecurityPolicy.Strict

        assertEquals(SecurityAction.BLOCK, strict.rootedDevice)
        assertEquals(SecurityAction.BLOCK, strict.debuggerAttached)
        assertEquals(SecurityAction.WARN, strict.debugBuild)
        assertEquals(SecurityAction.WARN, strict.emulator)
    }

    /** Verifies WarnOnly preset warns on all security violations */
    @Test
    fun securityPolicy_warnOnlyPreset_hasCorrectValues() {
        val warnOnly = KSafeSecurityPolicy.WarnOnly

        assertEquals(SecurityAction.WARN, warnOnly.rootedDevice)
        assertEquals(SecurityAction.WARN, warnOnly.debuggerAttached)
        assertEquals(SecurityAction.WARN, warnOnly.debugBuild)
        assertEquals(SecurityAction.WARN, warnOnly.emulator)
    }

    // ============ KSAFE SECURITY POLICY - CUSTOM CONFIGURATION ============

    /** Verifies custom policy allows mixing different actions per violation type */
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

    /** Verifies onViolation callback is stored and invocable */
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

        // Invoke the callback manually to test it works
        policy.onViolation.invoke(SecurityViolation.RootedDevice)

        assertTrue(callbackInvoked)
        assertEquals(SecurityViolation.RootedDevice, receivedViolation)
    }

    /** Verifies callback can receive all violation types */
    @Test
    fun securityPolicy_callbackReceivesAllViolationTypes() {
        val receivedViolations = mutableListOf<SecurityViolation>()

        val policy = KSafeSecurityPolicy(
            onViolation = { violation ->
                receivedViolations.add(violation)
            }
        )

        // Simulate receiving all violation types
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

    // ============ DATA CLASS BEHAVIOR ============

    /** Verifies data class equality based on field values */
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

    /** Verifies copy() creates modified instance without mutating original */
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

    /** Verifies hashCode consistency for equal objects */
    @Test
    fun securityPolicy_hashCode() {
        val policy1 = KSafeSecurityPolicy(rootedDevice = SecurityAction.WARN)
        val policy2 = KSafeSecurityPolicy(rootedDevice = SecurityAction.WARN)

        assertEquals(policy1.hashCode(), policy2.hashCode())
    }

    // ============ PRESET POLICIES ARE SINGLETONS ============

    /** Verifies preset policies return same instance (singleton pattern) */
    @Test
    fun securityPolicy_presetsAreSingletons() {
        // Same reference should be returned each time
        assertTrue(KSafeSecurityPolicy.Default === KSafeSecurityPolicy.Default)
        assertTrue(KSafeSecurityPolicy.Strict === KSafeSecurityPolicy.Strict)
        assertTrue(KSafeSecurityPolicy.WarnOnly === KSafeSecurityPolicy.WarnOnly)
    }

    // ============ PARTIAL CONFIGURATION ============

    /** Verifies unspecified fields default to IGNORE when partially configuring */
    @Test
    fun securityPolicy_partialConfiguration_otherFieldsRemainDefault() {
        val policy = KSafeSecurityPolicy(
            rootedDevice = SecurityAction.BLOCK
        )

        assertEquals(SecurityAction.BLOCK, policy.rootedDevice)
        assertEquals(SecurityAction.IGNORE, policy.debuggerAttached) // Default
        assertEquals(SecurityAction.IGNORE, policy.debugBuild) // Default
        assertEquals(SecurityAction.IGNORE, policy.emulator) // Default
    }
}
