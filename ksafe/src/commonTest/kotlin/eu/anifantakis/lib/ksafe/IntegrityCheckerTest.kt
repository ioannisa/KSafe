package eu.anifantakis.lib.ksafe

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Tests for [IntegrityResult] sealed class.
 *
 * Note: Platform-specific IntegrityChecker behavior is tested in platform tests.
 * These tests focus on the common IntegrityResult API.
 */
class IntegrityCheckerTest {

    // ============ INTEGRITY RESULT SUCCESS ============

    /** Verifies Success result stores token and platform correctly */
    @Test
    fun integrityResult_success_containsToken() {
        val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        val result = IntegrityResult.Success(token = token, platform = "android")

        assertEquals(token, result.token)
        assertEquals("android", result.platform)
    }

    /** Verifies Success result works with Android platform identifier */
    @Test
    fun integrityResult_success_androidPlatform() {
        val result = IntegrityResult.Success(token = "test_token", platform = "android")
        assertEquals("android", result.platform)
    }

    /** Verifies Success result works with iOS platform identifier */
    @Test
    fun integrityResult_success_iosPlatform() {
        val result = IntegrityResult.Success(token = "test_token", platform = "ios")
        assertEquals("ios", result.platform)
    }

    /** Verifies data class equality based on token and platform values */
    @Test
    fun integrityResult_success_equality() {
        val result1 = IntegrityResult.Success(token = "token123", platform = "android")
        val result2 = IntegrityResult.Success(token = "token123", platform = "android")
        val result3 = IntegrityResult.Success(token = "different", platform = "android")

        assertEquals(result1, result2)
        assertFalse(result1 == result3)
    }

    /** Verifies copy() creates modified Success without mutating original */
    @Test
    fun integrityResult_success_copy() {
        val original = IntegrityResult.Success(token = "original", platform = "android")
        val copied = original.copy(platform = "ios")

        assertEquals("original", copied.token)
        assertEquals("ios", copied.platform)
    }

    // ============ INTEGRITY RESULT ERROR ============

    /** Verifies Error result stores message with null code */
    @Test
    fun integrityResult_error_containsMessage() {
        val message = "Play Services not available"
        val result = IntegrityResult.Error(message = message)

        assertEquals(message, result.message)
        assertNull(result.code)
    }

    /** Verifies Error result stores both message and error code */
    @Test
    fun integrityResult_error_containsMessageAndCode() {
        val message = "API error"
        val code = 403
        val result = IntegrityResult.Error(message = message, code = code)

        assertEquals(message, result.message)
        assertEquals(code, result.code)
    }

    /** Verifies error code parameter is optional (nullable) */
    @Test
    fun integrityResult_error_codeIsOptional() {
        val result = IntegrityResult.Error(message = "Error without code")
        assertNull(result.code)
    }

    /** Verifies data class equality based on message and code values */
    @Test
    fun integrityResult_error_equality() {
        val result1 = IntegrityResult.Error(message = "Error", code = 100)
        val result2 = IntegrityResult.Error(message = "Error", code = 100)
        val result3 = IntegrityResult.Error(message = "Error", code = 200)

        assertEquals(result1, result2)
        assertNotEquals(result1, result3)
    }

    // ============ INTEGRITY RESULT NOT SUPPORTED ============

    /** Verifies NotSupported is a singleton data object */
    @Test
    fun integrityResult_notSupported_isSingleton() {
        val result1 = IntegrityResult.NotSupported
        val result2 = IntegrityResult.NotSupported

        assertSame(result1, result2)
    }

    /** Verifies NotSupported equality with itself */
    @Test
    fun integrityResult_notSupported_equality() {
        assertEquals(IntegrityResult.NotSupported, IntegrityResult.NotSupported)
    }

    // ============ SEALED CLASS BEHAVIOR ============

    /** Verifies when expression covers all sealed class variants exhaustively */
    @Test
    fun integrityResult_whenExpression_exhaustive() {
        val results = listOf<IntegrityResult>(
            IntegrityResult.Success(token = "token", platform = "android"),
            IntegrityResult.Error(message = "error"),
            IntegrityResult.NotSupported
        )

        results.forEach { result ->
            val description = when (result) {
                is IntegrityResult.Success -> "success: ${result.token}"
                is IntegrityResult.Error -> "error: ${result.message}"
                is IntegrityResult.NotSupported -> "not supported"
            }
            assertNotNull(description)
        }
    }

    /** Verifies type checking with assertIs for each sealed class variant */
    @Test
    fun integrityResult_isChecks() {
        val success: IntegrityResult = IntegrityResult.Success("token", "android")
        val error: IntegrityResult = IntegrityResult.Error("error")
        val notSupported: IntegrityResult = IntegrityResult.NotSupported

        assertIs<IntegrityResult.Success>(success)
        assertIs<IntegrityResult.Error>(error)
        assertIs<IntegrityResult.NotSupported>(notSupported)
    }

    // ============ TYPICAL USAGE PATTERNS ============

    /** Demonstrates typical Success handling pattern - extract token for server */
    @Test
    fun integrityResult_handleSuccess() {
        val result: IntegrityResult = IntegrityResult.Success(
            token = "integrity_token_xyz",
            platform = "android"
        )

        var tokenToSend: String? = null

        when (result) {
            is IntegrityResult.Success -> {
                tokenToSend = result.token
            }
            is IntegrityResult.Error -> {
                // Handle error
            }
            is IntegrityResult.NotSupported -> {
                // Handle not supported
            }
        }

        assertEquals("integrity_token_xyz", tokenToSend)
    }

    /** Demonstrates typical Error handling pattern - extract message and code */
    @Test
    fun integrityResult_handleError() {
        val result: IntegrityResult = IntegrityResult.Error(
            message = "Network error",
            code = 503
        )

        var errorMessage: String? = null
        var errorCode: Int? = null

        when (result) {
            is IntegrityResult.Success -> {
                // Handle success
            }
            is IntegrityResult.Error -> {
                errorMessage = result.message
                errorCode = result.code
            }
            is IntegrityResult.NotSupported -> {
                // Handle not supported
            }
        }

        assertEquals("Network error", errorMessage)
        assertEquals(503, errorCode)
    }

    /** Demonstrates typical NotSupported handling - trigger fallback behavior */
    @Test
    fun integrityResult_handleNotSupported() {
        val result: IntegrityResult = IntegrityResult.NotSupported

        var fallbackUsed = false

        when (result) {
            is IntegrityResult.Success -> {
                // Handle success
            }
            is IntegrityResult.Error -> {
                // Handle error
            }
            is IntegrityResult.NotSupported -> {
                fallbackUsed = true
            }
        }

        assertTrue(fallbackUsed)
    }
}
