package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Regression test for deep-review #64: per-entry key deletion runs AFTER the batch is already
 * committed to disk, so a failure in `engine.deleteKey` must not be reported as a failed batch.
 * Previously it propagated out of `processWrites`, so the awaiting `delete()` threw even though
 * the value had been removed from storage (and the post-commit cache swap was skipped). The
 * cleanup is now best-effort.
 */
class JvmDeleteKeyCleanupFailureTest {

    /** Encrypts/decrypts like [FakeEncryption], but `deleteKey` always throws — simulating a
     *  Keystore/Keychain delete hiccup during the post-commit cleanup. */
    private class DeleteKeyFailEncryption : KSafeEncryption {
        private val xor = FakeEncryption()
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray =
            xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)
        override fun decrypt(identifier: String, data: ByteArray): ByteArray = xor.decrypt(identifier, data)
        override fun deleteKey(identifier: String) { throw RuntimeException("simulated key-delete failure") }
    }

    @Test
    fun suspendDelete_succeeds_evenWhenPostCommitKeyDeleteFails() = runTest {
        val ksafe = KSafe(
            fileName = JvmKSafeTest.generateUniqueFileName(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = DeleteKeyFailEncryption(),
        )

        ksafe.put("token", "secret", KSafeWriteMode.Encrypted())
        assertEquals("secret", ksafe.get("token", "none"))

        // delete() routes through the coalescer and runs engine.deleteKey AFTER the storage
        // delete commits. Pre-fix, the thrown deleteKey failed the whole (committed) batch and
        // this suspend call threw; now it's best-effort, so delete() completes normally...
        ksafe.delete("token")

        // ...and the value really is gone from storage (the commit happened before the cleanup).
        assertEquals("none", ksafe.get("token", "none"), "the delete must have persisted despite the key-delete failure")

        ksafe.close()
    }
}
