package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.File
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.random.Random
import org.junit.runner.RunWith
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: no unexpected throw and no hang under randomized concurrency on a starved runner — the
 * failure class of the 2.2.0 cold-start race. Mid-run value assertions would be racy, so correctness
 * is checked at the quiesced boundaries: write + read-back, rotation, cold reopen. Off unless
 * `-PksafeTorture` (it burns `ksafe.torture.seconds`, default 45); replay with `-PksafeTortureSeed`.
 */
@RunWith(SkipConditionRunner::class)
@SkipUnless(TortureEnabled::class)
class JvmTortureTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_torture_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    private val runSeconds = System.getProperty("ksafe.torture.seconds")?.toLongOrNull() ?: 45L
    private val seed = System.getProperty("ksafe.torture.seed")?.toLongOrNull() ?: Random.nextLong()

    private val keys = List(24) { "k$it" }
    private val workers = 8

    @kotlinx.serialization.Serializable
    data class Payload(val id: Int, val text: String)

    @Test
    fun randomizedConcurrencyTorture() {
        println("KSafe torture: seed=$seed seconds=$runSeconds workers=$workers")

        val unexpected = ConcurrentLinkedQueue<Throwable>()
        val phases = 3
        val phaseMs = (runSeconds * 1000) / phases
        var ksafe = KSafe(fileName = "torture", baseDir = tmp)

        try {
            runBlocking {
                repeat(phases) { phase ->
                    // Chaos window.
                    val deadline = System.currentTimeMillis() + phaseMs
                    val jobs = (0 until workers).map { workerId ->
                        launch(Dispatchers.Default) {
                            val rnd = Random(seed + phase * 1000 + workerId)
                            while (System.currentTimeMillis() < deadline) {
                                val key = keys[rnd.nextInt(keys.size)]
                                try {
                                    when (rnd.nextInt(100)) {
                                        in 0..29 -> ksafe.putDirect(key, rnd.nextInt(), randomMode(rnd))
                                        in 30..44 -> ksafe.put(key, "s${rnd.nextInt()}", randomMode(rnd))
                                        in 45..69 -> ksafe.getDirect(key, -1)
                                        in 70..79 -> ksafe.get(key, "d")
                                        in 80..87 -> ksafe.deleteDirect(key)
                                        in 88..91 -> ksafe.delete(key)
                                        in 92..95 -> ksafe.getFlow(key, Payload(0, "d")).first()
                                        in 96..97 -> {
                                            // Cancellation chaos: a suspend write abandoned mid-flight.
                                            val j = launch { ksafe.put(key, Payload(rnd.nextInt(), "x"), randomMode(rnd)) }
                                            delay(rnd.nextLong(3))
                                            j.cancel()
                                        }
                                        98 -> ksafe.clearAll()
                                        else -> try {
                                            ksafe.rotateKeys()
                                        } catch (e: IllegalStateException) {
                                            /* a concurrent rotation is running — documented */
                                        }
                                    }
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: Throwable) {
                                    unexpected.add(e)
                                }
                            }
                        }
                    }
                    jobs.joinAll()

                    // Quiesced boundary: deterministic values for every key, then read back through
                    // the live instance, after a rotation, and after a cold reopen.
                    runCatching {
                        val recs = ksafe.core.storage.snapshot().keys.filter { it.startsWith("ksafe_key_") }.sorted()
                        println(
                            "TORTURE-POSTCHAOS phase=$phase gen=${ksafe.core.currentKeyGeneration.get()} " +
                                "engine=${System.identityHashCode(ksafe.core.engine)} " +
                                "storage=${System.identityHashCode(ksafe.core.storage)} keyrecs=$recs"
                        )
                    }
                    withContext(Dispatchers.Default) {
                        for ((i, key) in keys.withIndex()) {
                            ksafe.put(key, Payload(phase * 1000 + i, "phase$phase"), randomMode(Random(seed + i)))
                        }
                        for ((i, key) in keys.withIndex()) {
                            assertEquals(
                                Payload(phase * 1000 + i, "phase$phase"),
                                ksafe.get(key, Payload(-1, "missing")),
                                "phase $phase: '$key' must read back after quiesce (seed=$seed)",
                            )
                        }
                        runCatching {
                            val pre = ksafe.core.storage.snapshot().keys.filter { it.startsWith("ksafe_key_") }.sorted()
                            println("TORTURE-PREROTATE phase=$phase gen=${ksafe.core.currentKeyGeneration.get()} keyrecs=$pre")
                        }
                        val rotation = ksafe.rotateKeys()
                        runCatching {
                            val post = ksafe.core.storage.snapshot().keys.filter { it.startsWith("ksafe_key_") }.sorted()
                            println("TORTURE-POSTROTATE phase=$phase gen=${ksafe.core.currentKeyGeneration.get()} rotated=${rotation.rotated} skipped=${rotation.skipped} keyrecs=$post")
                        }
                        assertEquals(0, rotation.failed, "phase $phase: rotation must not fail entries (seed=$seed)")
                        for ((i, key) in keys.withIndex()) {
                            assertEquals(
                                Payload(phase * 1000 + i, "phase$phase"),
                                ksafe.get(key, Payload(-1, "missing")),
                                "phase $phase: '$key' must read back after rotation (seed=$seed)",
                            )
                        }
                    }

                    // Pre-close forensics: which engine key records are on disk at this point.
                    runCatching {
                        val snap = ksafe.core.storage.snapshot()
                        val recs = snap.keys.filter { it.startsWith("ksafe_key_") }.sorted()
                        println("TORTURE-PRECLOSE phase=$phase gen=${ksafe.core.currentKeyGeneration.get()} keyrecs=$recs")
                    }

                    // Close with writes potentially still queued (the 2.2.1 teardown guarantee:
                    // nothing hangs), then reopen cold and verify everything decrypts.
                    repeat(50) { ksafe.putDirect("burst$it", it) }
                    withTimeout(15_000) {
                        ksafe.close()
                        ksafe = KSafe(fileName = "torture", baseDir = tmp)
                        runCatching {
                            println(
                                "TORTURE-REOPEN phase=$phase " +
                                    "engine=${System.identityHashCode(ksafe.core.engine)} " +
                                    "storage=${System.identityHashCode(ksafe.core.storage)}"
                            )
                        }
                        for ((i, key) in keys.withIndex()) {
                            val expected = Payload(phase * 1000 + i, "phase$phase")
                            val actual = ksafe.get(key, Payload(-1, "missing"))
                            if (actual != expected) dumpDiagnostics(ksafe, key, phase)
                            assertEquals(
                                expected, actual,
                                "phase $phase: '$key' must decrypt after cold reopen (seed=$seed)",
                            )
                        }
                    }
                }
            }
        } finally {
            runCatching { ksafe.close() }
        }

        if (unexpected.isNotEmpty()) {
            val sample = unexpected.take(5).joinToString("\n") { "  ${it::class.simpleName}: ${it.message}" }
            throw AssertionError(
                "torture run (seed=$seed) hit ${unexpected.size} unexpected exception(s):\n$sample",
                unexpected.first(),
            )
        }
        assertTrue(true)
    }

    /** Failure forensics: the raw on-disk state behind a key that did not read back. */
    private suspend fun dumpDiagnostics(ksafe: KSafe, key: String, phase: Int) {
        runCatching {
            val snap = ksafe.core.storage.snapshot()
            val meta = snap[eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager.metadataRawKey(key)]
            val value = snap[eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager.valueRawKey(key)]
            val keygen = snap[eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager.KEYGEN_RAW_KEY]
            println("TORTURE-DIAG phase=$phase key=$key meta=$meta valuePresent=${value != null} keygen=$keygen gen=${ksafe.core.currentKeyGeneration.get()}")
            println("TORTURE-DIAG encMeta=${ksafe.core.encMetaMap[key]}")
            snap.keys.filter { it.startsWith("ksafe_key_") || (it.startsWith("__ksafe_") && !it.startsWith("__ksafe_value_") && !it.startsWith("__ksafe_meta_")) }
                .sorted().forEach { println("TORTURE-DIAG keyrec: $it") }
            tmp.walkTopDown().filter { it.isFile }.forEach { println("TORTURE-DIAG file: ${it.relativeTo(tmp)} (${it.length()}b)") }
        }.onFailure { println("TORTURE-DIAG failed: $it") }
    }

    private fun randomMode(rnd: Random): KSafeWriteMode = when (rnd.nextInt(4)) {
        0 -> KSafeWriteMode.Plain
        1 -> KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED)
        2 -> KSafeWriteMode.Encrypted(requireUnlockedDevice = true)
        else -> KSafeWriteMode.Encrypted()
    }
}

private object TortureEnabled : SkipCondition {
    override fun skipReason(): String? =
        if (System.getProperty("ksafe.torture") != null) null else "enable with -PksafeTorture"
}
