package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.runBlocking
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Locks in: on JVM (no biometric hardware) every static [KSafeBiometrics] method is a no-op that
 * succeeds. The same `actual`s back Kotlin/JS and Kotlin/Wasm, so JVM coverage suffices.
 */
class KSafeBiometricsJvmTest {

    @Test
    fun verifyBiometric_returnsTrue_onJvm() = runBlocking {
        val ok = KSafeBiometrics.verifyBiometric("Authenticate")
        assertTrue(ok, "verifyBiometric must return true on JVM (no-op)")
    }

    @Test
    fun verifyBiometric_acceptsAuthorizationDuration_onJvm() = runBlocking {
        val ok = KSafeBiometrics.verifyBiometric(
            reason = "Authenticate",
            authorizationDuration = BiometricAuthorizationDuration(60_000L, scope = "test"),
        )
        assertTrue(ok)
    }

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

    @Test
    fun clearBiometricAuth_doesNotThrow_onJvm() {
        KSafeBiometrics.clearBiometricAuth()
        KSafeBiometrics.clearBiometricAuth(scope = null)
        KSafeBiometrics.clearBiometricAuth(scope = "settings")
        // Reaching here means none of those calls threw.
    }

    @Test
    fun ksafeBiometrics_isAStaticSingleton() {
        val ref1: Any = KSafeBiometrics
        val ref2: Any = KSafeBiometrics
        assertNotNull(ref1)
        assertTrue(ref1 === ref2, "KSafeBiometrics must be a Kotlin object singleton")
    }

    @Test
    fun verifyBiometric_biometricsOnly_returnsTrueOnJvm() = runBlocking {
        val ok = KSafeBiometrics.verifyBiometric(
            reason = "Authenticate",
            allowDeviceCredentialFallback = false,
        )
        assertTrue(ok, "verifyBiometric with allowDeviceCredentialFallback=false must return true on JVM")
    }

    @Test
    fun verifyBiometric_credentialFallbackExplicitTrue_returnsTrueOnJvm() = runBlocking {
        val ok = KSafeBiometrics.verifyBiometric(
            reason = "Authenticate",
            allowDeviceCredentialFallback = true,
        )
        assertTrue(ok)
    }

    @Test
    fun verifyBiometric_biometricsOnly_withAuthorizationDuration_returnsTrueOnJvm() = runBlocking {
        val ok = KSafeBiometrics.verifyBiometric(
            reason = "Authenticate",
            authorizationDuration = BiometricAuthorizationDuration(60_000L, scope = "test"),
            allowDeviceCredentialFallback = false,
        )
        assertTrue(ok)
    }

    @Test
    fun verifyBiometricDirect_biometricsOnly_callsOnResultWithTrueOnJvm() {
        val result = AtomicBoolean(false)
        val latch = CountDownLatch(1)

        KSafeBiometrics.verifyBiometricDirect(
            reason = "Authenticate",
            allowDeviceCredentialFallback = false,
        ) { ok ->
            result.set(ok)
            latch.countDown()
        }

        assertTrue(latch.await(2, TimeUnit.SECONDS))
        assertTrue(result.get(), "Callback must receive true on JVM even with allowDeviceCredentialFallback=false")
    }

    @Test
    fun verifyBiometricDirect_biometricsOnly_withAuthorizationDuration_callsOnResultOnJvm() {
        val result = AtomicBoolean(false)
        val latch = CountDownLatch(1)

        KSafeBiometrics.verifyBiometricDirect(
            reason = "Authenticate",
            authorizationDuration = BiometricAuthorizationDuration(60_000L, scope = "test"),
            allowDeviceCredentialFallback = false,
        ) { ok ->
            result.set(ok)
            latch.countDown()
        }

        assertTrue(latch.await(2, TimeUnit.SECONDS))
        assertTrue(result.get())
    }
}
