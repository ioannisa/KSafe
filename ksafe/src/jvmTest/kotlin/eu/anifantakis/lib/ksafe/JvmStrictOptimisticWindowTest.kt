package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import java.util.concurrent.CountDownLatch
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * FEEDBACK_4 FB3-M1: a strict (`requireUnlockedDevice`) write puts the PLAINTEXT
 * into `memoryCache` optimistically and marks the entry strict, then the write
 * consumer swaps it to ciphertext post-batch. In the window between the optimistic
 * put and the swap, a read used to fall through to that cached plaintext (the
 * decrypt attempt fails non-transiently — plaintext isn't valid base64 — and the
 * old fallback returned the cached value), so the secret was readable from RAM
 * without the device being unlocked. A strict read must return the default when
 * native-decrypt did not succeed, never the transiently-cached plaintext.
 */
class JvmStrictOptimisticWindowTest {

    /** Pins the write consumer inside `encrypt` (before the plaintext→ciphertext swap)
     *  so the test can observe the optimistic window deterministically. */
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
                    "encrypted (FB3-M1) — the read must return the default",
            )
        } finally {
            engine.release.countDown()
            ksafe.close()
        }
    }
}
