package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.runBlocking
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in what a macOS/Windows JVM does when its native bridge (the ObjC runtime / COM over JNA)
 * fails to load: the prompt path exists but cannot be used, so a strict call refuses, a permissive
 * one keeps the documented pass-through, and availability reports `false`. Linux has no prompt
 * path at all and keeps passing through in both modes ([DesktopBridgeHeadlessProbeTest]).
 */
@RunWith(SkipConditionRunner::class)
@SkipUnless(PromptsOn::class, OnMacOrWindows::class)
class DesktopBridgeLoadFailureTest {

    private var priorPromptsProperty: String? = null
    private val stderr = ByteArrayOutputStream()
    private lateinit var realErr: PrintStream

    @BeforeTest
    fun simulateAFailedBridgeLoad() {
        priorPromptsProperty = System.getProperty("ksafe.biometrics.jvm.prompts")
        System.clearProperty("ksafe.biometrics.jvm.prompts")
        desktopBridgeLoadedOverrideForTest = false
        KSafeBiometrics.clearBiometricAuth()
        realErr = System.err
        System.setErr(PrintStream(stderr, true))
    }

    @AfterTest
    fun restore() {
        System.setErr(realErr)
        desktopBridgeLoadedOverrideForTest = null
        desktopPromptOverrideForTest = null
        priorPromptsProperty?.let { System.setProperty("ksafe.biometrics.jvm.prompts", it) }
        KSafeBiometrics.clearBiometricAuth()
    }

    @Test
    fun strictVerify_refuses_andSaysSo() = runBlocking {
        assertFalse(
            KSafeBiometrics.verifyBiometric("Authenticate", allowDeviceCredentialFallback = false),
            "a strict gate must not open because its bridge failed to load",
        )
        assertTrue(
            stderr.toString().contains("strict verifyBiometric (allowDeviceCredentialFallback=false) refused"),
            "the refusal must be explained on stderr:\n$stderr",
        )
    }

    @Test
    fun strictVerifyDirect_reportsFalse() {
        val latch = CountDownLatch(1)
        var direct = true
        KSafeBiometrics.verifyBiometricDirect("Authenticate", allowDeviceCredentialFallback = false) { ok ->
            direct = ok
            latch.countDown()
        }
        assertTrue(latch.await(15, TimeUnit.SECONDS), "callback within 15s")
        assertFalse(direct, "the callback door must refuse the strict call too")
    }

    @Test
    fun permissiveVerify_keepsTheDocumentedPassThrough() = runBlocking {
        assertTrue(KSafeBiometrics.verifyBiometric("Authenticate"))
        assertTrue(KSafeBiometrics.verifyBiometric("Authenticate", allowDeviceCredentialFallback = true))

        val latch = CountDownLatch(1)
        var direct = false
        KSafeBiometrics.verifyBiometricDirect("Authenticate") { ok -> direct = ok; latch.countDown() }
        assertTrue(latch.await(15, TimeUnit.SECONDS), "callback within 15s")
        assertTrue(direct)
    }

    @Test
    fun biometricsAvailable_reportsFalse_inBothModes() = runBlocking {
        assertFalse(KSafeBiometrics.biometricsAvailable())
        assertFalse(KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false))

        val latch = CountDownLatch(1)
        var direct = true
        KSafeBiometrics.biometricsAvailableDirect(allowDeviceCredentialFallback = false) { ok ->
            direct = ok
            latch.countDown()
        }
        assertTrue(latch.await(15, TimeUnit.SECONDS), "callback within 15s")
        assertFalse(direct)
    }

    @Test
    fun refusedStrictCall_doesNotSeedTheAuthorizationCache() = runBlocking {
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")
        assertFalse(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = false))

        val strictKey = BiometricAuthSession.cacheKey(duration, allowDeviceCredentialFallback = false)
        assertFalse(
            BiometricSessionStore.isFresh(strictKey, duration),
            "a refused strict call must leave its cache slot empty",
        )

        // With a prompt path back (the seam stands in for the bridge), the same scope must still prompt.
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; true }
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = false))
        assertEquals(1, prompts, "the refused strict call must not have opened a prompt-free window")
    }
}

private object OnMacOrWindows : SkipCondition {
    override fun skipReason(): String? = if (HostOs.isOther) "no prompt path on Linux/other" else null
}
