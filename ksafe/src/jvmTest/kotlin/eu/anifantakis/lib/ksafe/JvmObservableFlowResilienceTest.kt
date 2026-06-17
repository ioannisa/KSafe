package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A **transient** decrypt failure (locked device / busy Keystore) on a
 * snapshot must not be rethrown out of `getFlowRaw`'s flow — it would
 * propagate uncaught out of long-lived observers' `viewModelScope` /
 * Recomposer, crash the app, and permanently kill observation. The flow must
 * **skip** that emission and stay alive.
 */
class JvmObservableFlowResilienceTest {

    /** Encrypts like the XOR [FakeEncryption], but `decrypt` throws a *transient* error
     *  (matches `isTransientDecryptFailure`) while [failTransient] is set. */
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

    @Test
    fun getFlow_skipsTransientDecryptFailure_insteadOfThrowing() = runBlocking {
        val engine = ToggleTransientEngine()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            lazyLoad = true,
            testEngine = engine,
        )
        ksafe.put("k", "v1", KSafeWriteMode.Encrypted())

        // Sanity: decrypts fine when not armed.
        assertEquals("v1", withTimeoutOrNull(2_000) { ksafe.getFlow<String>("k", "def").first() })

        // Armed: the emission's decrypt fails transiently. It must be skipped →
        // no emission → timeout (null), NOT an exception out of first().
        engine.failTransient = true
        val result = withTimeoutOrNull(500) { ksafe.getFlow<String>("k", "def").first() }
        assertNull(result, "a transient decrypt failure must be skipped, not crash the flow")

        ksafe.close()
    }

    /** decrypt fails with an Apple-Keychain-shaped transient error whose message contains
     *  "Keychain" but NOT "device is locked"/"Keystore". */
    private class KeychainErrorEngine : KSafeEncryption {
        @Volatile var fail = false
        private val xor = FakeEncryption()
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray =
            xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
            if (fail) throw IllegalStateException("KSafe: Keychain error -25308 for account $identifier")
            return xor.decrypt(identifier, data)
        }
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun keychainTransientError_isClassifiedTransient_andSkipped() = runBlocking {
        // A transient Apple Keychain error ("Keychain error …", no "device is locked"/
        // "Keystore") must be classified as transient — skipped on the flow path, not
        // emitted as the default.
        val engine = KeychainErrorEngine()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            lazyLoad = true,
            testEngine = engine,
        )
        ksafe.put("k", "v1", KSafeWriteMode.Encrypted())
        assertEquals("v1", withTimeoutOrNull(2_000) { ksafe.getFlow<String>("k", "def").first() })

        engine.fail = true
        val result = withTimeoutOrNull(500) { ksafe.getFlow<String>("k", "def").first() }
        assertNull(result, "a transient Keychain error must be skipped (transient), not emitted as the default")

        ksafe.close()
    }

    @Test
    fun getFlow_staysAlive_afterTransientSkip_andEmitsNextGoodValue() = runBlocking {
        val engine = ToggleTransientEngine()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            lazyLoad = true,
            testEngine = engine,
        )
        ksafe.put("k", "v1", KSafeWriteMode.Encrypted())

        engine.failTransient = true
        val collected = mutableListOf<String>()
        val job = launch(Dispatchers.Default) {
            ksafe.getFlow<String>("k", "def").collect { collected.add(it) }
        }
        delay(200) // first snapshot's decrypt is skipped; the flow (and job) must stay alive

        // Recover and write a new value → a fresh snapshot the flow can decrypt.
        engine.failTransient = false
        ksafe.put("k", "v2", KSafeWriteMode.Encrypted())
        delay(400)
        job.cancel()

        assertTrue(
            collected.contains("v2"),
            "the flow must survive a transient skip and emit the next decryptable value; got $collected",
        )
        ksafe.close()
    }
}
