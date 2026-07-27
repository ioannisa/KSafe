package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import kotlinx.coroutines.test.runTest
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in the two properties a rotation over a LARGE store has to keep, both of which the
 * per-entry tests are blind to because they never rotate enough entries to reach the limit.
 *
 * 1. Every entry rotates, however many there are — no straggler left on the old generation.
 * 2. Only a bounded number of entries are decrypted at once. Rotation is the one operation
 *    that holds plaintext for entries the caller never asked for, so how much of the store
 *    can be in the clear simultaneously is a property in its own right, independent of
 *    whatever loop shape produces it.
 */
class JvmRotationConcurrencyBoundTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_rotbound_${System.nanoTime()}").apply { mkdirs() }

    @AfterTest fun tearDown() { tmp.deleteRecursively() }

    /**
     * Counts entries between their decrypt and the re-encrypt that consumes the plaintext.
     * The suspend entry points are interface defaults delegating to these, so counting here
     * catches the rotation path.
     */
    private class InFlightCountingEngine : StatefulFakeEncryption() {
        private val inFlight = AtomicInteger(0)
        val peak = AtomicInteger(0)
        /** Rotation decrypts; the writes that seed the store do not, so this isolates it. */
        @Volatile var counting = false

        override fun decrypt(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            if (counting) {
                val now = inFlight.incrementAndGet()
                peak.updateAndGet { if (now > it) now else it }
            }
            return super.decrypt(identifier, data, requireUnlockedDevice, aad)
        }

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            val out = super.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)
            if (counting) inFlight.decrementAndGet()
            return out
        }
    }

    @Test
    fun everyEntryRotates_wellPastTheInFlightLimit() = runTest {
        val engine = InFlightCountingEngine()
        val ksafe = KSafe(fileName = "rotbound_all", baseDir = tmp, testEngine = engine)
        // Several times the in-flight limit, so the rotation cannot finish in one pass of it.
        val n = KSafeCore.ROTATION_IN_FLIGHT * 4 + 7

        repeat(n) { ksafe.put("k$it", "value-$it", KSafeWriteMode.Encrypted()) }

        val result = ksafe.rotateKeys()

        assertEquals(n, result.rotated, "every entry must rotate, not just the first batch")
        assertEquals(0, result.skipped, "nothing raced these writes, so nothing may be skipped")
        assertEquals(0, result.failed, "no entry may fail")
        assertEquals(2, result.keyGeneration)

        // Reading proves the alias bookkeeping, not just the counters: the fake derives its
        // key from the alias, so an entry left on the old generation reads back garbage.
        repeat(n) { assertEquals("value-$it", ksafe.get("k$it", "GONE"), "entry $it survived rotation") }
        ksafe.close()
    }

    @Test
    fun noMoreThanTheLimitIsHeldInTheClearAtOnce() = runTest {
        val engine = InFlightCountingEngine()
        val ksafe = KSafe(fileName = "rotbound_peak", baseDir = tmp, testEngine = engine)
        val n = KSafeCore.ROTATION_IN_FLIGHT * 4 + 7

        repeat(n) { ksafe.put("k$it", "value-$it", KSafeWriteMode.Encrypted()) }
        engine.counting = true

        ksafe.rotateKeys()

        assertTrue(
            engine.peak.get() <= KSafeCore.ROTATION_IN_FLIGHT,
            "rotation held ${engine.peak.get()} entries in the clear at once, above the " +
                "${KSafeCore.ROTATION_IN_FLIGHT} it bounds itself to",
        )
        assertTrue(
            engine.peak.get() > 1,
            "sanity: rotation is supposed to overlap entries — a peak of ${engine.peak.get()} " +
                "means the bound is being met by doing one at a time",
        )
        ksafe.close()
    }
}
