package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
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
import kotlin.time.Duration.Companion.seconds

/** The JVM actual's own OS split, reproduced so a test can gate on the branch it exercises. */
internal object HostOs {
    private val name = System.getProperty("os.name").orEmpty().lowercase()
    val isMac: Boolean = name.contains("mac") || name.contains("darwin")
    val isWindows: Boolean = name.contains("windows")
    val isOther: Boolean = !isMac && !isWindows
}

/**
 * Headless probes of the real native bridges, no seams: every call is one the OS answers without
 * UI, so a CI runner never sees a dialog, and each is bounded so broken marshalling fails the test
 * instead of hanging the job. The other operating systems' branches report as skipped.
 */
@RunWith(SkipConditionRunner::class)
@SkipUnless(PromptsOn::class)
class DesktopBridgeHeadlessProbeTest {

    private var priorPromptsProperty: String? = null

    @BeforeTest
    fun promptsOn() {
        // The opt-out must not be what makes these pass.
        priorPromptsProperty = System.getProperty("ksafe.biometrics.jvm.prompts")
        System.clearProperty("ksafe.biometrics.jvm.prompts")
        KSafeBiometrics.clearBiometricAuth()
    }

    @AfterTest
    fun restore() {
        priorPromptsProperty?.let { System.setProperty("ksafe.biometrics.jvm.prompts", it) }
        KSafeBiometrics.clearBiometricAuth()
    }

    // ---- macOS: LAContext over the ObjC runtime ----

    @Test
    @SkipUnless(OnMac::class)
    fun mac_bridgeLoads_andBothProbesAnswerWithoutUi() {
        assertTrue(MacLocalAuthentication.isAvailable, "the ObjC/LocalAuthentication bridge must load on macOS")

        val strict = bounded { MacLocalAuthentication.canEvaluate(allowDeviceCredentialFallback = false) }
        val permissive = bounded { MacLocalAuthentication.canEvaluate(allowDeviceCredentialFallback = true) }
        if (strict) assertTrue(permissive, "biometrics is a subset of device-owner auth")

        // The public probe must be this very answer, not a cached or opted-out one.
        assertEquals(strict, bounded { KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false) })
        assertEquals(permissive, bounded { KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = true) })
    }

    @Test
    @SkipUnless(OnMac::class, MacBridgeLoaded::class, NoTouchId::class)
    fun mac_strictEvaluate_withoutTouchId_returnsFalsePromptly_andShowsNothing() {
        // The reply block and its anchors run for real here; LA answers with an error, no dialog.
        assertFalse(bounded { MacLocalAuthentication.evaluate("KSafe headless probe", allowDeviceCredentialFallback = false) })
        assertFalse(
            bounded { KSafeBiometrics.verifyBiometric("KSafe headless probe", allowDeviceCredentialFallback = false) },
            "strict verify on a Mac without Touch ID must refuse, not pass through",
        )
    }

    /** An empty `localizedReason` raises `NSInvalidArgumentException` through JNA and aborts the JVM. */
    @Test
    @SkipUnless(OnMac::class, MacBridgeLoaded::class, NoTouchId::class)
    fun mac_blankReason_neverReachesEvaluatePolicy() {
        assertFalse(bounded { MacLocalAuthentication.evaluate("", allowDeviceCredentialFallback = false) })
        assertFalse(bounded { MacLocalAuthentication.evaluate("   ", allowDeviceCredentialFallback = false) })
        assertFalse(bounded { KSafeBiometrics.verifyBiometric("", allowDeviceCredentialFallback = false) })
    }

    // ---- Windows: UserConsentVerifier over COM ----

    @Test
    @SkipUnless(OnWindows::class)
    fun windows_bridgeLoads_andAvailabilityProbeAnswersWithoutUi() {
        assertTrue(WindowsHello.isAvailable, "the combase/user32/kernel32 bridge must load on Windows")

        // CheckAvailabilityAsync never shows UI; evaluate() is deliberately not exercised here.
        val hello = bounded { WindowsHello.checkAvailability() }
        assertEquals(hello, bounded { KSafeBiometrics.biometricsAvailable() })
        assertEquals(hello, bounded { KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false) })
    }

    // ---- Everything else (Linux): no prompt path ----

    @Test
    @SkipUnless(OnOther::class)
    fun other_verifyPassesThrough_availabilityIsFalse_andNoBridgeIsTouched() {

        val stderr = ByteArrayOutputStream()
        val realErr = System.err
        System.setErr(PrintStream(stderr, true))
        try {
            assertFalse(bounded { KSafeBiometrics.biometricsAvailable() })
            assertFalse(bounded { KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false) })

            assertTrue(bounded { KSafeBiometrics.verifyBiometric("Authenticate") })
            assertTrue(bounded { KSafeBiometrics.verifyBiometric("Authenticate", allowDeviceCredentialFallback = false) })
            assertTrue(
                bounded {
                    KSafeBiometrics.verifyBiometric(
                        "Authenticate",
                        authorizationDuration = BiometricAuthorizationDuration(60_000L, scope = "linux"),
                    )
                },
            )

            val latch = CountDownLatch(1)
            var direct = false
            KSafeBiometrics.verifyBiometricDirect("Authenticate") { ok -> direct = ok; latch.countDown() }
            assertTrue(latch.await(15, TimeUnit.SECONDS), "callback within 15s")
            assertTrue(direct)
        } finally {
            System.setErr(realErr)
        }
        // A bridge touched on Linux fails to load and says so on stderr.
        assertFalse(
            stderr.toString().contains("bridge unavailable"),
            "the no-prompt branch must not construct a native bridge:\n$stderr",
        )
    }

}

private val PROBE_TIMEOUT = 15.seconds

// Detached, so a native call that never returns strands one IO thread instead of the test.
private val probeScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

private fun <T> bounded(block: suspend () -> T): T = runBlocking {
    val result = probeScope.async { block() }
    withTimeout(PROBE_TIMEOUT) { result.await() }
}

internal object PromptsOn : SkipCondition {
    override fun skipReason(): String? =
        if (desktopPromptsDisabled()) "KSAFE_BIOMETRICS_JVM_PROMPTS=off in the environment" else null
}

private object OnMac : SkipCondition {
    override fun skipReason(): String? = if (HostOs.isMac) null else "macOS only"
}

private object OnWindows : SkipCondition {
    override fun skipReason(): String? = if (HostOs.isWindows) null else "Windows only"
}

private object OnOther : SkipCondition {
    override fun skipReason(): String? = if (HostOs.isOther) null else "Linux/other only"
}

private object MacBridgeLoaded : SkipCondition {
    override fun skipReason(): String? = if (MacLocalAuthentication.isAvailable) null else "bridge unavailable"
}

/** A strict evaluate on a Mac with Touch ID enrolled would show a real prompt. */
private object NoTouchId : SkipCondition {
    override fun skipReason(): String? =
        if (bounded { MacLocalAuthentication.canEvaluate(allowDeviceCredentialFallback = false) }) {
            "Touch ID is enrolled on this Mac"
        } else {
            null
        }
}
