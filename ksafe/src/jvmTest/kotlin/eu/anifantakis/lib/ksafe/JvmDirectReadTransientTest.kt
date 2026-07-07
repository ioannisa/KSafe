package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Locks in: the non-suspend read path (getDirect, the by-property value delegate, and the getStateFlow seed) returns the caller's default on a transient decrypt failure, while suspend get() still throws so callers can await unlock and retry.
 */
class JvmDirectReadTransientTest {

    /** XOR-encrypts, but `decrypt` throws a TRANSIENT (device-locked) error while armed. */
    private class ToggleTransientEngine : KSafeEncryption {
        @Volatile var failTransient = false
        private val xor = FakeEncryption()
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray =
            xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
            if (failTransient) throw IllegalStateException("KSafe: Cannot access Keystore key - device is locked.")
            return xor.decrypt(identifier, data)
        }
        override fun deleteKey(identifier: String) {}
    }

    private fun newKsafe(engine: KSafeEncryption) = KSafe(
        fileName = JvmKSafeTest.generateUniqueFileName(),
        memoryPolicy = KSafeMemoryPolicy.ENCRYPTED, // cacheHoldsCiphertext → every read decrypts
        lazyLoad = true,
        testEngine = engine,
    )

    @Test
    fun getDirect_returnsDefault_onTransientDecryptFailure() = runBlocking {
        val engine = ToggleTransientEngine()
        val ksafe = newKsafe(engine)
        ksafe.put("k", "v1", KSafeWriteMode.Encrypted())
        assertEquals("v1", ksafe.getDirect("k", "def"), "sanity: reads back when unlocked")

        engine.failTransient = true
        assertEquals(
            "def", ksafe.getDirect("k", "def"),
            "getDirect must return the default on a transient decrypt failure, not throw",
        )
        ksafe.close()
    }

    @Test
    fun byPropertyValueDelegate_returnsDefault_onTransientDecryptFailure() {
        val engine = ToggleTransientEngine()
        val ksafe = newKsafe(engine)
        runBlocking { ksafe.put("k", "v1", KSafeWriteMode.Encrypted()) }

        engine.failTransient = true
        val value: String by ksafe("def", key = "k")
        assertEquals("def", value, "a `by ksafe(...)` value read must return the default on a locked device")
        ksafe.close()
    }

    @Test
    fun getStateFlowSeed_doesNotThrow_onTransientDecryptFailure() {
        val engine = ToggleTransientEngine()
        val ksafe = newKsafe(engine)
        runBlocking { ksafe.put("k", "v1", KSafeWriteMode.Encrypted()) }

        engine.failTransient = true
        val scope = CoroutineScope(SupervisorJob())
        try {
            // getStateFlow seeds its initial value synchronously via getDirectRaw — this
            // must not throw during StateFlow construction on a locked device.
            val sf = ksafe.getStateFlow("k", "def", scope)
            assertEquals("def", sf.value, "the StateFlow seed must fall back to the default, not crash")
        } finally {
            scope.cancel()
            ksafe.close()
        }
    }

    @Test
    fun suspendGet_stillThrows_onTransientDecryptFailure() {
        // Guard rail: the suspend get() path keeps throwing so coroutine callers can
        // await unlock and retry — the intentional asymmetry with getDirect.
        val engine = ToggleTransientEngine()
        val ksafe = newKsafe(engine)
        runBlocking { ksafe.put("k", "v1", KSafeWriteMode.Encrypted()) }

        engine.failTransient = true
        assertFailsWith<IllegalStateException> {
            runBlocking { ksafe.get("k", "def") }
        }
        engine.failTransient = false
        ksafe.close()
    }
}
