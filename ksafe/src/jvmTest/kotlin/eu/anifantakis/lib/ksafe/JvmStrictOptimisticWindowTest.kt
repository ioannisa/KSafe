package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Locks in: during a strict (requireUnlockedDevice) write's optimistic window — plaintext cached before the post-batch swap to ciphertext — a read returns the default, never the transiently-cached plaintext.
 */
class JvmStrictOptimisticWindowTest {

    /** Parks the write consumer inside `encrypt` (before the plaintext→ciphertext swap) so the optimistic window is observable. */
    private class PinEncryptEngine : KSafeEncryption {
        val encryptEntered = CountDownLatch(1)
        val release = CountDownLatch(1)
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray {
            encryptEntered.countDown()
            release.await()
            return data
        }
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun strictEntry_plaintextNotReadableFromOptimisticWindow() {
        val engine = PinEncryptEngine()
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            lazyLoad = true,
            testEngine = engine,
        )
        try {
            // Strict write; the consumer picks it up and parks inside encrypt BEFORE the
            // post-batch swap, so memoryCache still holds the optimistic PLAINTEXT.
            ksafe.putDirect("k", "top-secret", KSafeWriteMode.Encrypted(requireUnlockedDevice = true))
            engine.encryptEntered.await()

            assertEquals(
                "default", ksafe.getDirect("k", "default"),
                "a strict entry's optimistic plaintext must NOT be readable from RAM before it is " +
                    "encrypted — the read must return the default",
            )
        } finally {
            engine.release.countDown()
            ksafe.close()
        }
    }
}
