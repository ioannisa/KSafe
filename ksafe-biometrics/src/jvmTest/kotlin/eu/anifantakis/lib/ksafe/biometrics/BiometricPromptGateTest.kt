package eu.anifantakis.lib.ksafe.biometrics

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Concurrency contract for [BiometricPromptGate]: prompts are serialized (never two in
 * flight) and a cancelled holder releases the gate. The gate is platform-agnostic, so it's
 * exercised on the JVM with real threads.
 */
class BiometricPromptGateTest {

    @Test
    fun serializesConcurrentPrompts_neverTwoInFlight() = runBlocking(Dispatchers.Default) {
        val gate = BiometricPromptGate()
        val active = AtomicInteger(0)
        val maxActive = AtomicInteger(0)

        (0 until 16).map {
            async {
                gate.withSinglePrompt {
                    val now = active.incrementAndGet()
                    maxActive.getAndUpdate { m -> maxOf(m, now) }
                    delay(15) // hold the "prompt" open
                    active.decrementAndGet()
                }
            }
        }.awaitAll()

        assertEquals(
            1, maxActive.get(),
            "at most one biometric prompt may be in flight at a time",
        )
    }

    @Test
    fun cancelledHolder_releasesGate_soNextCallerProceeds() = runBlocking {
        val gate = BiometricPromptGate()

        // First caller acquires the gate and never resolves (a prompt the user ignores).
        val acquired = CompletableDeferred<Unit>()
        val holder = launch(Dispatchers.Default) {
            gate.withSinglePrompt {
                acquired.complete(Unit)
                awaitCancellation()
            }
        }
        acquired.await()

        // Its UI flow is cancelled — the gate must be released, not stranded.
        holder.cancelAndJoin()

        val proceeded = withTimeout(2_000) {
            gate.withSinglePrompt { true }
        }
        assertTrue(proceeded, "a cancelled holder must release the gate so the next caller is not stuck")
    }
}
