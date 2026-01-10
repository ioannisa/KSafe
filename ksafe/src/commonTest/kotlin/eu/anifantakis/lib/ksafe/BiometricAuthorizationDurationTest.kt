package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tests for [BiometricAuthorizationDuration] data class.
 */
class BiometricAuthorizationDurationTest {

    // ============ BASIC CONSTRUCTION ============

    /** Verifies construction with duration only (scope defaults to null) */
    @Test
    fun biometricAuthorizationDuration_withDurationOnly() {
        val duration = BiometricAuthorizationDuration(duration = 30_000L)

        assertEquals(30_000L, duration.duration)
        assertNull(duration.scope)
    }

    /** Verifies construction with both duration and scope */
    @Test
    fun biometricAuthorizationDuration_withDurationAndScope() {
        val duration = BiometricAuthorizationDuration(
            duration = 60_000L,
            scope = "settings_screen"
        )

        assertEquals(60_000L, duration.duration)
        assertEquals("settings_screen", duration.scope)
    }

    /** Verifies scope defaults to null for global authorization */
    @Test
    fun biometricAuthorizationDuration_defaultScopeIsNull() {
        val duration = BiometricAuthorizationDuration(duration = 5_000L)
        assertNull(duration.scope, "Default scope should be null")
    }

    // ============ DURATION VALUES ============

    /** Verifies 1 minute (60000ms) duration is stored correctly */
    @Test
    fun biometricAuthorizationDuration_oneMinute() {
        val oneMinute = 60_000L
        val duration = BiometricAuthorizationDuration(duration = oneMinute)
        assertEquals(60_000L, duration.duration)
    }

    /** Verifies 5 minutes (300000ms) duration is stored correctly */
    @Test
    fun biometricAuthorizationDuration_fiveMinutes() {
        val fiveMinutes = 5 * 60 * 1000L
        val duration = BiometricAuthorizationDuration(duration = fiveMinutes)
        assertEquals(300_000L, duration.duration)
    }

    /** Verifies 30 seconds (30000ms) duration is stored correctly */
    @Test
    fun biometricAuthorizationDuration_thirtySeconds() {
        val thirtySeconds = 30_000L
        val duration = BiometricAuthorizationDuration(duration = thirtySeconds)
        assertEquals(30_000L, duration.duration)
    }

    // ============ SCOPE PATTERNS ============

    /** Verifies screen-based scope identifier pattern */
    @Test
    fun biometricAuthorizationDuration_screenIdScope() {
        val duration = BiometricAuthorizationDuration(
            duration = 60_000L,
            scope = "profile_screen"
        )
        assertEquals("profile_screen", duration.scope)
    }

    /** Verifies user-based scope identifier pattern */
    @Test
    fun biometricAuthorizationDuration_userIdScope() {
        val duration = BiometricAuthorizationDuration(
            duration = 120_000L,
            scope = "user_12345"
        )
        assertEquals("user_12345", duration.scope)
    }

    /** Verifies ViewModel hashCode as scope (recommended pattern) */
    @Test
    fun biometricAuthorizationDuration_viewModelHashScope() {
        // Simulating viewModelScope.hashCode().toString()
        val viewModelHash = "1234567890"
        val duration = BiometricAuthorizationDuration(
            duration = 60_000L,
            scope = viewModelHash
        )
        assertEquals(viewModelHash, duration.scope)
    }

    /** Verifies null scope for global authorization cache */
    @Test
    fun biometricAuthorizationDuration_nullScopeForGlobal() {
        val duration = BiometricAuthorizationDuration(
            duration = 60_000L,
            scope = null
        )
        assertNull(duration.scope)
    }

    // ============ DATA CLASS BEHAVIOR ============

    /** Verifies equality for same duration and scope */
    @Test
    fun biometricAuthorizationDuration_equality_sameDurationSameScope() {
        val duration1 = BiometricAuthorizationDuration(60_000L, "scope1")
        val duration2 = BiometricAuthorizationDuration(60_000L, "scope1")

        assertEquals(duration1, duration2)
    }

    /** Verifies inequality for different durations */
    @Test
    fun biometricAuthorizationDuration_equality_differentDuration() {
        val duration1 = BiometricAuthorizationDuration(60_000L, "scope1")
        val duration2 = BiometricAuthorizationDuration(30_000L, "scope1")

        assertNotEquals(duration1, duration2)
    }

    /** Verifies inequality for different scopes */
    @Test
    fun biometricAuthorizationDuration_equality_differentScope() {
        val duration1 = BiometricAuthorizationDuration(60_000L, "scope1")
        val duration2 = BiometricAuthorizationDuration(60_000L, "scope2")

        assertNotEquals(duration1, duration2)
    }

    /** Verifies inequality between null and non-null scope */
    @Test
    fun biometricAuthorizationDuration_equality_nullVsNonNullScope() {
        val duration1 = BiometricAuthorizationDuration(60_000L, null)
        val duration2 = BiometricAuthorizationDuration(60_000L, "scope1")

        assertNotEquals(duration1, duration2)
    }

    /** Verifies copy() with duration change preserves scope */
    @Test
    fun biometricAuthorizationDuration_copy_changeDuration() {
        val original = BiometricAuthorizationDuration(60_000L, "scope1")
        val copied = original.copy(duration = 120_000L)

        assertEquals(60_000L, original.duration)
        assertEquals(120_000L, copied.duration)
        assertEquals(original.scope, copied.scope)
    }

    /** Verifies copy() with scope change preserves duration */
    @Test
    fun biometricAuthorizationDuration_copy_changeScope() {
        val original = BiometricAuthorizationDuration(60_000L, "scope1")
        val copied = original.copy(scope = "scope2")

        assertEquals("scope1", original.scope)
        assertEquals("scope2", copied.scope)
        assertEquals(original.duration, copied.duration)
    }

    /** Verifies hashCode consistency for equal objects */
    @Test
    fun biometricAuthorizationDuration_hashCode_sameForEqualObjects() {
        val duration1 = BiometricAuthorizationDuration(60_000L, "scope1")
        val duration2 = BiometricAuthorizationDuration(60_000L, "scope1")

        assertEquals(duration1.hashCode(), duration2.hashCode())
    }

    // ============ EDGE CASES ============

    /** Verifies empty string is valid scope value */
    @Test
    fun biometricAuthorizationDuration_emptyStringScope() {
        val duration = BiometricAuthorizationDuration(60_000L, "")
        assertEquals("", duration.scope)
    }

    /** Verifies very long scope string is handled */
    @Test
    fun biometricAuthorizationDuration_veryLongScope() {
        val longScope = "a".repeat(1000)
        val duration = BiometricAuthorizationDuration(60_000L, longScope)
        assertEquals(longScope, duration.scope)
    }

    /** Verifies zero duration is allowed (validation elsewhere) */
    @Test
    fun biometricAuthorizationDuration_zeroDuration() {
        // While 0 duration might not make practical sense,
        // the data class should allow it (validation is elsewhere)
        val duration = BiometricAuthorizationDuration(0L, null)
        assertEquals(0L, duration.duration)
    }

    /** Verifies negative duration is allowed (validation elsewhere) */
    @Test
    fun biometricAuthorizationDuration_negativeDuration() {
        // While negative duration doesn't make sense,
        // the data class should allow it (validation is elsewhere)
        val duration = BiometricAuthorizationDuration(-1000L, null)
        assertEquals(-1000L, duration.duration)
    }

    /** Verifies Long.MAX_VALUE duration is handled */
    @Test
    fun biometricAuthorizationDuration_maxLongDuration() {
        val duration = BiometricAuthorizationDuration(Long.MAX_VALUE, null)
        assertEquals(Long.MAX_VALUE, duration.duration)
    }
}
