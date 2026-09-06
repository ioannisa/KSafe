package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: the JVM desktop-prompt dispatch — a denial propagates as `false`, a success seeds the
 * authorization cache in strength-keyed slots, and the WinRT pinterface-GUID computation the
 * Windows Hello bridge depends on reproduces published reference GUIDs. The OS prompt is replaced
 * by the test seam, so no real dialogs appear.
 */
class DesktopBiometricsTest {

    @BeforeTest
    fun reset() {
        KSafeBiometrics.clearBiometricAuth()
    }

    @AfterTest
    fun tearDown() {
        desktopPromptOverrideForTest = null
        desktopAvailabilityOverrideForTest = null
        KSafeBiometrics.clearBiometricAuth()
    }

    @Test
    fun promptDenial_propagatesAsFalse() = runBlocking {
        desktopPromptOverrideForTest = { _, _ -> false }
        assertFalse(
            KSafeBiometrics.verifyBiometric("Authenticate"),
            "a denied/cancelled desktop prompt must return false — the legacy always-true would mask it",
        )
    }

    /**
     * A blank reason must never reach the OS layer: Apple's `evaluatePolicy` raises
     * `NSInvalidArgumentException` for an empty `localizedReason`, and that raise kills the
     * process instead of failing the call.
     */
    @Test
    fun blankReason_reachesThePlatformAsTheBuiltInDefault() = runBlocking {
        val seen = mutableListOf<String>()
        desktopPromptOverrideForTest = { reason, _ -> seen += reason; true }

        assertTrue(KSafeBiometrics.verifyBiometric(reason = ""))
        assertTrue(KSafeBiometrics.verifyBiometric(reason = "   "))
        assertTrue(KSafeBiometrics.verifyBiometric(reason = "Unlock the vault"))

        assertEquals(
            listOf("Authenticate to continue", "Authenticate to continue", "Unlock the vault"),
            seen,
        )
    }

    @Test
    fun blankReason_isAlsoNormalisedByTheDirectDoor() {
        val seen = mutableListOf<String>()
        val latch = java.util.concurrent.CountDownLatch(1)
        desktopPromptOverrideForTest = { reason, _ -> seen += reason; true }

        KSafeBiometrics.verifyBiometricDirect(reason = "") { latch.countDown() }

        assertTrue(latch.await(2, java.util.concurrent.TimeUnit.SECONDS), "callback within 2s")
        assertEquals(listOf("Authenticate to continue"), seen)
    }

    @Test
    fun promptSuccess_returnsTrue_andSeedsTheCache() = runBlocking {
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; true }

        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")
        assertTrue(KSafeBiometrics.verifyBiometric("Authenticate", duration))
        assertEquals(1, prompts)

        assertTrue(KSafeBiometrics.verifyBiometric("Authenticate", duration))
        assertEquals(1, prompts, "a cached authorization must not re-prompt inside its window")
    }

    @Test
    fun permissiveSuccess_neverSatisfiesABiometricsOnlyCall() = runBlocking {
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; true }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = true))
        assertEquals(1, prompts)

        // The cache is keyed by strength, so the two calls occupy different slots.
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = false))
        assertEquals(2, prompts, "a strict call must re-prompt despite a cached permissive success")
    }

    @Test
    fun promptFailure_doesNotSeedTheCache() = runBlocking {
        val answers = ArrayDeque(listOf(false, true))
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; answers.removeFirst() }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertFalse(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(2, prompts)
    }

    @Test
    fun clearBiometricAuth_revokesTheCachedWindow() = runBlocking {
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; true }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        KSafeBiometrics.clearBiometricAuth(scope = "vault")
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(2, prompts, "clearBiometricAuth must force the next call back to a prompt")
    }

    @Test
    fun clearDuringAnInFlightPrompt_isNotUndoneByItsSuccess() = runBlocking {
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ ->
            prompts++
            // Logout raced the open prompt: revocation lands before the user completes it.
            if (prompts == 1) KSafeBiometrics.clearBiometricAuth()
            true
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration), "the in-flight caller still gets its result")
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(2, prompts, "a success landing after clearBiometricAuth must not re-seed the window")
    }

    @Test
    fun scopedClearDuringAnInFlightPrompt_revokesThatScope() = runBlocking {
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ ->
            prompts++
            if (prompts == 1) KSafeBiometrics.clearBiometricAuth(scope = "vault")
            true
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(2, prompts, "a scoped clear during the prompt must keep the next call prompting")
    }

    @Test
    fun scopedClearOfAnUnrelatedScope_doesNotRevokeTheInFlightPrompt() = runBlocking {
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ ->
            prompts++
            if (prompts == 1) KSafeBiometrics.clearBiometricAuth(scope = "other")
            true
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration))
        assertEquals(1, prompts, "revoking an unrelated scope must not cost this scope its seeded window")
    }

    @Test
    fun concurrentCalls_areSerialized_neverTwoPromptsInFlight() = runBlocking(Dispatchers.Default) {
        val active = AtomicInteger(0)
        val maxActive = AtomicInteger(0)
        desktopPromptOverrideForTest = { _, _ ->
            val now = active.incrementAndGet()
            maxActive.getAndUpdate { m -> maxOf(m, now) }
            Thread.sleep(20) // hold the "prompt" open
            active.decrementAndGet()
            true
        }

        (0 until 6).map {
            async { KSafeBiometrics.verifyBiometric("Auth") }
        }.awaitAll()

        assertEquals(1, maxActive.get(), "desktop prompts must be serialized — never two OS dialogs at once")
    }

    @Test
    fun queuedCaller_skipsThePrompt_whenTheHolderJustAuthorizedItsScope() = runBlocking(Dispatchers.Default) {
        val prompts = AtomicInteger(0)
        val firstPromptShowing = CompletableDeferred<Unit>()
        desktopPromptOverrideForTest = { _, _ ->
            prompts.incrementAndGet()
            firstPromptShowing.complete(Unit)
            Thread.sleep(30) // keep the prompt open so the second caller queues behind the gate
            true
        }
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")

        val first = async { KSafeBiometrics.verifyBiometric("Auth", duration) }
        firstPromptShowing.await()
        val second = async { KSafeBiometrics.verifyBiometric("Auth", duration) }

        assertTrue(first.await())
        assertTrue(second.await())
        assertEquals(1, prompts.get(), "a caller queued behind a successful same-scope prompt must not re-prompt")
    }

    /**
     * The single-shot version above only exposes the redundant prompt when the scheduler happens to
     * cooperate — roughly one loaded-CI run in fifteen. Repeating the handoff makes it a reliable
     * signal: the queued caller must see the holder's authorization the instant it takes the gate.
     */
    @Test
    fun queuedCaller_neverRePrompts_acrossRepeatedHandoffs() = runBlocking(Dispatchers.Default) {
        repeat(400) { iteration ->
            KSafeBiometrics.clearBiometricAuth()
            val prompts = AtomicInteger(0)
            val firstPromptShowing = CompletableDeferred<Unit>()
            desktopPromptOverrideForTest = { _, _ ->
                prompts.incrementAndGet()
                firstPromptShowing.complete(Unit)
                Thread.sleep(1) // hold the gate just long enough for the second caller to queue
                true
            }
            val duration = BiometricAuthorizationDuration(60_000L, scope = "vault-$iteration")

            val first = async { KSafeBiometrics.verifyBiometric("Auth", duration) }
            firstPromptShowing.await()
            val second = async { KSafeBiometrics.verifyBiometric("Auth", duration) }

            assertTrue(first.await())
            assertTrue(second.await())
            assertEquals(
                1,
                prompts.get(),
                "iteration $iteration: the queued caller re-prompted — the holder's authorization " +
                    "was not visible when the gate changed hands",
            )
        }
    }

    @Test
    fun optOutProperty_restoresLegacyPassThrough() = runBlocking {
        // No seam here: the property short-circuits before any OS bridge is touched.
        val prior = System.getProperty("ksafe.biometrics.jvm.prompts")
        System.setProperty("ksafe.biometrics.jvm.prompts", "off")
        try {
            assertTrue(
                KSafeBiometrics.verifyBiometric("Authenticate"),
                "the opt-out property must restore the pre-2.2.0 always-true no-op",
            )
        } finally {
            prior?.let { System.setProperty("ksafe.biometrics.jvm.prompts", it) }
                ?: System.clearProperty("ksafe.biometrics.jvm.prompts")
        }
    }

    @Test
    fun optOutPassThrough_doesNotSeedTheAuthorizationCache() = runBlocking {
        // A pass-through is not an authentication: seeding one would hand a later real prompt a free ride.
        val prior = System.getProperty("ksafe.biometrics.jvm.prompts")
        System.setProperty("ksafe.biometrics.jvm.prompts", "off")
        val duration = BiometricAuthorizationDuration(60_000L, scope = "vault")
        try {
            assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = false))
            assertFalse(
                BiometricSessionStore.isFresh(
                    BiometricAuthSession.cacheKey(duration, allowDeviceCredentialFallback = false),
                    duration,
                ),
                "an opted-out pass-through must leave the strict slot empty",
            )

            assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = true))
            assertFalse(
                BiometricSessionStore.isFresh(
                    BiometricAuthSession.cacheKey(duration, allowDeviceCredentialFallback = true),
                    duration,
                ),
                "an opted-out pass-through must leave the permissive slot empty too",
            )
        } finally {
            prior?.let { System.setProperty("ksafe.biometrics.jvm.prompts", it) }
                ?: System.clearProperty("ksafe.biometrics.jvm.prompts")
        }

        // With prompts back on, the same scope must still prompt — the opt-out opened no window.
        var prompts = 0
        desktopPromptOverrideForTest = { _, _ -> prompts++; true }
        assertTrue(KSafeBiometrics.verifyBiometric("Auth", duration, allowDeviceCredentialFallback = false))
        assertEquals(1, prompts, "the pass-through must not have opened a prompt-free window")
    }

    // ---- biometricsAvailable ----

    @Test
    fun biometricsAvailable_reportsFalse_whenPromptsAreOptedOut() = runBlocking {
        // Opted-out verify is a pass-through → availability must report "no real prompt",
        // regardless of what the machine's real authenticator would say.
        val prior = System.getProperty("ksafe.biometrics.jvm.prompts")
        System.setProperty("ksafe.biometrics.jvm.prompts", "off")
        try {
            assertFalse(KSafeBiometrics.biometricsAvailable())
            assertFalse(KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false))
        } finally {
            prior?.let { System.setProperty("ksafe.biometrics.jvm.prompts", it) }
                ?: System.clearProperty("ksafe.biometrics.jvm.prompts")
        }
    }

    @Test
    fun biometricsAvailable_passesTheStrengthFlagThrough() = runBlocking {
        val flagsSeen = mutableListOf<Boolean>()
        desktopAvailabilityOverrideForTest = { allowFallback -> flagsSeen += allowFallback; allowFallback }

        assertTrue(KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = true))
        assertFalse(KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false))
        assertEquals(listOf(true, false), flagsSeen)
    }

    @Test
    fun biometricsAvailableDirect_deliversTheCallbackResult() {
        desktopAvailabilityOverrideForTest = { _ -> true }
        val latch = java.util.concurrent.CountDownLatch(1)
        var received = false
        KSafeBiometrics.biometricsAvailableDirect { available ->
            received = available
            latch.countDown()
        }
        assertTrue(latch.await(2, java.util.concurrent.TimeUnit.SECONDS), "callback within 2s")
        assertTrue(received)
    }

    // ---- WinRT pinterface GUID computation ----

    @Test
    fun pinterfaceGuid_reproducesPublishedReferenceGuids() {
        // IIterable<String> — published as __FIIterable_1_HSTRING in windows.foundation.collections.h
        assertEquals(
            "e2fcc7c1-3bfc-5a0b-b2b0-72e769d1cb7e",
            WinRtGuid.pinterfaceGuid("pinterface({faa585ea-6214-4217-afda-7f46de5869b3};string)"),
        )
        // IVector<String> — published as __FIVector_1_HSTRING
        assertEquals(
            "98b9acc1-4b56-532e-ac73-03d5291cca90",
            WinRtGuid.pinterfaceGuid("pinterface({913337e9-11a1-4345-a3a2-4e7f956e222d};string)"),
        )
    }

    @Test
    fun asyncOperationGuid_isStableAndWellFormed() {
        val guid = WinRtGuid.ASYNC_OP_USER_CONSENT
        assertTrue(
            Regex("^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").matches(guid),
            "pinterface GUID must be a v5 UUID with RFC 4122 variant; was $guid",
        )
    }

    @Test
    fun classifyResult_passesThroughOnlyGenuineUnavailability_blocksRealDenials() {
        // Raw UserConsentVerificationResult codes: 0=Verified, 1=DeviceNotPresent,
        // 2=NotConfiguredForUser, 3=DisabledByPolicy, 6=Canceled.
        assertTrue(WindowsHello.classifyResult(0, allowDeviceCredentialFallback = true), "Verified")
        assertTrue(WindowsHello.classifyResult(0, allowDeviceCredentialFallback = false), "Verified is always true")
        // A real denial blocks even in permissive mode — Hello was shown and refused.
        assertFalse(WindowsHello.classifyResult(6, allowDeviceCredentialFallback = true), "Canceled must block")
        assertTrue(WindowsHello.classifyResult(2, allowDeviceCredentialFallback = true), "NotConfigured + permissive → pass")
        assertFalse(WindowsHello.classifyResult(2, allowDeviceCredentialFallback = false), "NotConfigured + strict → refuse")
        assertFalse(WindowsHello.classifyResult(1, allowDeviceCredentialFallback = false), "DeviceNotPresent + strict → refuse")
        assertTrue(WindowsHello.classifyResult(3, allowDeviceCredentialFallback = true), "DisabledByPolicy + permissive → pass")
    }

    @Test
    fun vtableOffsets_scaleWithTheNativePointerSize() {
        // COM vtable entries are pointer-sized: 8-byte stride on 64-bit, 4 on a 32-bit JVM. A
        // literal stride would fetch the wrong function pointer and crash natively; there is no
        // Windows x86 JRE here, so this pins the arithmetic to the pointer size instead.
        assertEquals(0L, WindowsHello.vtableByteOffset(0))
        assertEquals(6L * com.sun.jna.Native.POINTER_SIZE, WindowsHello.vtableByteOffset(6))
        assertEquals(8L * com.sun.jna.Native.POINTER_SIZE, WindowsHello.vtableByteOffset(8))
        if (com.sun.jna.Native.POINTER_SIZE == 8) {
            assertEquals(48L, WindowsHello.vtableByteOffset(6), "64-bit host: slot 6 must sit at byte 48")
        }
    }

    @Test
    fun asyncOpUserConsent_usesTheNonFlagsEnumSignature() {
        // The reference GUIDs above cover string type-args only; this locks in the enum path.
        assertEquals(
            "fd596ffd-2318-558f-9dbe-d21df43764a5",
            WinRtGuid.ASYNC_OP_USER_CONSENT,
            "IAsyncOperation<UserConsentVerificationResult> must use the i4 (non-flags enum) signature",
        )
    }

    // ---- Live probe (opt-in): pops a real system prompt, so normal runs skip it ----

    @Test
    fun livePrompt_realSystemDialog_optIn() = runBlocking {
        if (System.getProperty("ksafe.biometrics.live") != "1") return@runBlocking
        val ok = KSafeBiometrics.verifyBiometric(
            reason = "KSafe biometrics live verification",
            allowDeviceCredentialFallback = true,
        )
        assertTrue(ok, "live probe: authentication was denied or the prompt failed")
    }
}
