package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.runBlocking
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * JVM-platform tests for the static [KSafeBiometrics] API.
 *
 * The JVM target has no biometric hardware, so the documented contract is that
 * every method is a no-op that succeeds. These tests pin down that contract.
 *
 * (The same `actual fun`s are used on Kotlin/JS and Kotlin/Wasm with identical
 * behaviour. JVM coverage is sufficient since it's the same source per platform.)
 */
class KSafeBiometricsJvmTest {

    /** `verifyBiometric` returns `true` on JVM (no biometric hardware → no-op). */
    @Test
    fun verifyBiometric_returnsTrue_onJvm() = runBlocking {
        val ok = KSafeBiometrics.verifyBiometric("Authenticate")
        assertTrue(ok, "verifyBiometric must return true on JVM (no-op)")
    }

    /** `verifyBiometric` honours an authorization-duration argument without throwing. */
    @Test
    fun verifyBiometric_acceptsAuthorizationDuration_onJvm() = runBlocking {
        val ok = KSafeBiometrics.verifyBiometric(
            reason = "Authenticate",
            authorizationDuration = BiometricAuthorizationDuration(60_000L, scope = "test"),
        )
        assertTrue(ok)
    }

    /** `verifyBiometricDirect` invokes the callback with `true` on JVM. */
    @Test
    fun verifyBiometricDirect_callsOnResultWithTrue_onJvm() {
        val result = AtomicBoolean(false)
        val callbackReceived = AtomicBoolean(false)
        val latch = CountDownLatch(1)

        KSafeBiometrics.verifyBiometricDirect("Authenticate") { ok ->
            result.set(ok)
            callbackReceived.set(true)
            latch.countDown()
        }

        assertTrue(
            latch.await(2, TimeUnit.SECONDS),
            "verifyBiometricDirect should invoke its callback within 2s",
        )
        assertTrue(callbackReceived.get(), "Callback must have been invoked")
        assertTrue(result.get(), "Callback must receive true on JVM")
    }

    /**
     * `verifyBiometricDirect` honours an authorization-duration argument and
     * still calls back with `true`.
     */
    @Test
    fun verifyBiometricDirect_acceptsAuthorizationDuration_onJvm() {
        val result = AtomicBoolean(false)
        val latch = CountDownLatch(1)

        KSafeBiometrics.verifyBiometricDirect(
            reason = "Authenticate",
            authorizationDuration = BiometricAuthorizationDuration(60_000L, scope = "test"),
        ) { ok ->
            result.set(ok)
            latch.countDown()
        }

        assertTrue(latch.await(2, TimeUnit.SECONDS))
        assertTrue(result.get())
    }

    /**
     * `clearBiometricAuth` is a no-op on JVM and must not throw — both with a
     * scope argument and without.
     */
    @Test
    fun clearBiometricAuth_doesNotThrow_onJvm() {
        KSafeBiometrics.clearBiometricAuth()
        KSafeBiometrics.clearBiometricAuth(scope = null)
        KSafeBiometrics.clearBiometricAuth(scope = "settings")
        // Reaching here means none of those calls threw.
    }

    /**
     * `BiometricHelper`'s configuration knobs are not exposed via the JVM source
     * set (it's an Android-only object), but `KSafeBiometrics` itself must
     * resolve as the same `object` everywhere. Sanity check: it's a non-null
     * singleton.
     */
    @Test
    fun ksafeBiometrics_isAStaticSingleton() {
        val ref1: Any = KSafeBiometrics
        val ref2: Any = KSafeBiometrics
        assertNotNull(ref1)
        assertTrue(ref1 === ref2, "KSafeBiometrics must be a Kotlin object singleton")
    }
}
