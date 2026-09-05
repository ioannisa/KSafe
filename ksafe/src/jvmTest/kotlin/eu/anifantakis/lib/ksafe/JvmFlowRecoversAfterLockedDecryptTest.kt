package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage
import eu.anifantakis.lib.ksafe.internal.coreparts.lockedDecryptRetryBackoffMs
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: a flow whose FIRST decrypt happens on a locked device recovers on its own once the
 * device unlocks, with no write landing in the store in between. Storage emits only on a `.data`
 * change or a local commit, so without a retry the observer stays at the caller's default forever
 * while `getDirect` already returns the real value.
 */
class JvmFlowRecoversAfterLockedDecryptTest {

    /** XOR engine whose `decrypt` throws the Android-Keystore-shaped transient failure while locked. */
    private class LockableEngine : KSafeEncryption {
        @Volatile var locked = false
        val decryptCalls = AtomicInteger(0)
        private val xor = FakeEncryption()

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray = xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)

        override fun decrypt(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            decryptCalls.incrementAndGet()
            if (locked) throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked.")
            return xor.decrypt(identifier, data, requireUnlockedDevice, aad)
        }

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    /** XOR engine whose `decrypt` throws a PERMANENT (missing key) failure while armed. */
    private class MissingKeyEngine : KSafeEncryption {
        @Volatile var fail = false
        val decryptCalls = AtomicInteger(0)
        private val xor = FakeEncryption()

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray = xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)

        override fun decrypt(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            decryptCalls.incrementAndGet()
            if (fail) throw IllegalStateException(KSafeEngineMessage.noKeyFound(identifier))
            return xor.decrypt(identifier, data, requireUnlockedDevice, aad)
        }

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    private fun openLocked(fileName: String, engine: KSafeEncryption): KSafe = KSafe(
        fileName = fileName,
        memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
        lazyLoad = true,
        testEngine = engine,
    )

    @Test
    fun getFlow_seededWhileLocked_recoversAfterUnlock_withNoWriteInBetween() = runBlocking {
        val engine = LockableEngine()
        val fileName = JvmKSafeTest.generateUniqueFileName()

        val seed = openLocked(fileName, engine)
        try {
            seed.put("k", "v1", KSafeWriteMode.Encrypted(requireUnlockedDevice = true))
        } finally {
            seed.close()
        }

        engine.locked = true
        val ksafe = openLocked(fileName, engine)
        val collected = mutableListOf<String>()
        val job = launch(Dispatchers.Default) {
            ksafe.getFlow("k", "").collect { collected.add(it) }
        }
        try {
            delay(1_000)
            assertFalse(
                collected.contains(""),
                "a transient decrypt failure must never surface as the caller's default; got $collected",
            )

            engine.locked = false // the device unlocks; nothing is written to the store
            withTimeout(10_000) {
                while (!collected.contains("v1")) delay(50)
            }
            assertFalse(
                collected.contains(""),
                "the default must not appear even after recovery; got $collected",
            )
        } finally {
            job.cancel()
            ksafe.close()
        }
    }

    @Test
    fun getStateFlow_seededWhileLocked_recoversAfterUnlock_withNoWriteInBetween() = runBlocking {
        val engine = LockableEngine()
        val fileName = JvmKSafeTest.generateUniqueFileName()

        val seed = openLocked(fileName, engine)
        try {
            seed.put("k", "v1", KSafeWriteMode.Encrypted(requireUnlockedDevice = true))
        } finally {
            seed.close()
        }

        engine.locked = true
        val ksafe = openLocked(fileName, engine)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val state = ksafe.getStateFlow("k", "", scope)
            assertEquals("", state.value, "seeding on a locked device yields the default (unchanged behaviour)")

            delay(1_000)
            engine.locked = false // no write, only the unlock
            withTimeout(10_000) {
                while (state.value != "v1") delay(50)
            }
        } finally {
            scope.cancel()
            ksafe.close()
        }
    }

    @Test
    fun getFlow_permanentDecryptFailure_emitsTheDefault_andDoesNotRetry() = runBlocking {
        val engine = MissingKeyEngine()
        val fileName = JvmKSafeTest.generateUniqueFileName()

        val seed = openLocked(fileName, engine)
        try {
            seed.put("k", "v1", KSafeWriteMode.Encrypted(requireUnlockedDevice = true))
        } finally {
            seed.close()
        }

        engine.fail = true
        val ksafe = openLocked(fileName, engine)
        val collected = mutableListOf<String>()
        val job = launch(Dispatchers.Default) {
            ksafe.getFlow("k", "def").collect { collected.add(it) }
        }
        try {
            withTimeout(5_000) {
                while (collected.isEmpty()) delay(25)
            }
            assertEquals(listOf("def"), collected, "a permanent failure resolves to the caller's default")

            val callsAfterFirstEmission = engine.decryptCalls.get()
            delay(1_500)
            assertEquals(
                callsAfterFirstEmission, engine.decryptCalls.get(),
                "a permanent failure must not resubscribe in a loop",
            )
            assertEquals(listOf("def"), collected, "and must not re-emit")
        } finally {
            job.cancel()
            ksafe.close()
        }
    }

    @Test
    fun lockedDecryptRetryBackoffMs_isExponentialThenCappedAt30s() {
        assertEquals(250L, lockedDecryptRetryBackoffMs(0))
        assertEquals(500L, lockedDecryptRetryBackoffMs(1))
        assertEquals(1_000L, lockedDecryptRetryBackoffMs(2))
        assertEquals(2_000L, lockedDecryptRetryBackoffMs(3))
        assertEquals(4_000L, lockedDecryptRetryBackoffMs(4))
        assertEquals(8_000L, lockedDecryptRetryBackoffMs(5))
        assertEquals(16_000L, lockedDecryptRetryBackoffMs(6))
        assertEquals(30_000L, lockedDecryptRetryBackoffMs(7))
        assertEquals(30_000L, lockedDecryptRetryBackoffMs(100), "must stay capped, never overflow the shift")
        assertTrue(lockedDecryptRetryBackoffMs(0) > collectorRetryBackoffMsFirstStep, "slower than the storage-read schedule")
    }

    private companion object {
        const val collectorRetryBackoffMsFirstStep = 50L
    }
}
