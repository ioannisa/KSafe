package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * FEEDBACK_4 M6: the suspend `get()` path rethrows a transient decrypt failure (locked device /
 * busy vault) — the intentional M-B/M-H asymmetry with `getDirect`. `getOrCreateSecret` relies on
 * `get<String>(key, "")` collapsing an unreadable secret to `""` so it can route to its documented
 * refuse-to-rotate error; the rethrow made it surface a RAW keystore exception instead (and risked
 * regenerating over a still-present secret). It must now catch the transient failure and raise the
 * well-formed refuse-to-rotate `IllegalStateException`, never a raw one, and never regenerate.
 */
class JvmGetOrCreateSecretTransientTest {

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
        memoryPolicy = KSafeMemoryPolicy.ENCRYPTED, // every read decrypts → the transient path is hit
        lazyLoad = true,
        testEngine = engine,
    )

    @Test
    fun getOrCreateSecret_onTransientFailure_refusesToRotate_withoutRawException_orRegeneration() = runBlocking {
        val engine = ToggleTransientEngine()
        val ksafe = newKsafe(engine)

        // First call generates + stores the secret.
        val secret1 = ksafe.getOrCreateSecret(key = "db")
        assertTrue(secret1.isNotEmpty())

        // Device locks → the secret can't be read back this call.
        engine.failTransient = true
        val ex = assertFailsWith<IllegalStateException> {
            runBlocking { ksafe.getOrCreateSecret(key = "db") }
        }
        // It must be the well-formed refuse-to-rotate error, NOT the raw keystore exception.
        assertTrue(
            ex.message?.contains("could not be read back", ignoreCase = true) == true,
            "must surface the documented refuse-to-rotate error, was: ${ex.message}",
        )
        assertTrue(
            ex.message?.contains("device is locked", ignoreCase = true) != true,
            "must NOT surface the raw keystore exception, was: ${ex.message}",
        )

        // Device unlocks → the ORIGINAL secret is returned (never regenerated).
        engine.failTransient = false
        val secret2 = ksafe.getOrCreateSecret(key = "db")
        assertContentEquals(secret1, secret2, "the existing secret must survive a transient-failure call — never rotated")

        ksafe.close()
    }
}
