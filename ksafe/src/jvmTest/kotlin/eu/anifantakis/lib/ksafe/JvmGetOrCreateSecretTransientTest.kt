package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Locks in: when a transient decrypt failure prevents reading back an existing secret, getOrCreateSecret raises the well-formed refuse-to-rotate IllegalStateException (never a raw keystore exception) and never regenerates, so the original secret survives.
 */
class JvmGetOrCreateSecretTransientTest {

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

        val secret1 = ksafe.getOrCreateSecret(key = "db")
        assertTrue(secret1.isNotEmpty())

        // Device locks → the secret can't be read back this call.
        engine.failTransient = true
        val ex = assertFailsWith<IllegalStateException> {
            runBlocking { ksafe.getOrCreateSecret(key = "db") }
        }
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
