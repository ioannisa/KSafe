package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Tests for [getOrCreateSecret]'s "never silently rotate" contract.
 *
 * A `get(key, "")` read returns `""` both when the secret is absent AND when
 * it EXISTS yet can't be decrypted (the backing key was invalidated/rotated,
 * the vault is unavailable, or the ciphertext is corrupt). The two must be
 * distinguished via [KSafe.getKeyInfo], and the existing-but-unreadable case
 * must throw rather than mint a replacement: silently rotating the secret
 * permanently orphans everything encrypted under the old one — e.g. a
 * SQLCipher database keyed by it would never open again.
 *
 * Uses [KSafeMemoryPolicy.ENCRYPTED] so every read goes through the engine's
 * `decrypt` (no plaintext side-cache), letting a single instance flip from
 * "readable" to "unreadable" deterministically without reopen/disk-flush timing.
 */
class JvmGetOrCreateSecretTest {

    /**
     * Encrypts like the XOR [FakeEncryption], but `decrypt` fails as if the
     * ciphertext were corrupt whenever [failDecrypt] is set — simulating an
     * invalidated key / unavailable vault / tampered blob.
     */
    private class ToggleEngine : KSafeEncryption {
        @Volatile var failDecrypt = false
        private val xor = FakeEncryption()

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
        ): ByteArray = xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray {
            if (failDecrypt) {
                throw IllegalStateException("KSafe: simulated ciphertext corruption (AEAD tag mismatch)")
            }
            return xor.decrypt(identifier, data)
        }

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    @Test
    fun firstCallGeneratesAndSubsequentCallsReturnTheSameSecret() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        val first = ksafe.getOrCreateSecret("main_db")
        assertEquals(32, first.size, "default secret length is 256-bit")

        val second = ksafe.getOrCreateSecret("main_db")
        assertContentEquals(first, second, "idempotent: subsequent calls return the same secret")

        ksafe.close()
    }

    @Test
    fun existingButUnreadableSecretThrowsInsteadOfSilentlyRotating() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val engine = ToggleEngine()
        val ksafe = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            testEngine = engine,
        )

        // Create a real secret (this is the passphrase a SQLCipher DB would use).
        val original = ksafe.getOrCreateSecret("main_db")
        assertEquals(32, original.size)

        // The secret still EXISTS on disk, but now reads back undecryptable
        // (key invalidated / vault down / corrupt). get(storageKey, "") → "".
        engine.failDecrypt = true

        val ex = assertFailsWith<IllegalStateException> {
            ksafe.getOrCreateSecret("main_db")
        }
        assertTrue(
            ex.message?.contains("exists but could not be read back") == true,
            "must surface the unreadable-secret condition rather than rotate; was: ${ex.message}",
        )

        // The decisive check: it must NOT have minted a replacement. Once the
        // entry is readable again, the ORIGINAL secret must still be what's
        // stored — proving no silent rotation happened during the outage.
        engine.failDecrypt = false
        val afterRecovery = ksafe.getOrCreateSecret("main_db")
        assertContentEquals(
            original, afterRecovery,
            "secret must be unchanged — getOrCreateSecret must never silently rotate it",
        )

        ksafe.close()
    }

    @Test
    fun genuinelyAbsentSecretIsStillGeneratedEvenWhenUnrelatedEntriesExist() = runTest {
        // The fix must not break first-time creation just because the store
        // already holds other (unrelated) data.
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        ksafe.put("unrelated", "value")

        val secret = ksafe.getOrCreateSecret("brand_new_db")
        assertEquals(32, secret.size, "absent secret must still be generated")

        ksafe.close()
    }

    /** Encrypts like the XOR [FakeEncryption], but `decrypt` always fails — as if
     *  the backing key were invalidated/unreadable on a later cold start. */
    private class AlwaysFailDecryptEngine : KSafeEncryption {
        private val xor = FakeEncryption()
        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
        ): ByteArray = xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray =
            throw IllegalStateException("KSafe: simulated unreadable secret (key invalidated)")

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    @Test
    fun underPlainTextPolicy_unreadableSecretOnColdStart_throwsInsteadOfRotating() = runTest {
        // Under KSafeMemoryPolicy.PLAIN_TEXT the secret is decrypted at
        // cold-start load; if that fails the entry is dropped from memoryCache.
        // The never-rotate guard must detect existence via protectionMap
        // (on-disk metadata, populated regardless of decryptability), not
        // memoryCache alone — otherwise it would see "absent" and mint a
        // replacement, permanently orphaning the original.
        val fileName = JvmKSafeTest.generateUniqueFileName()

        // Instance 1 — create the secret successfully under PLAIN_TEXT.
        val k1 = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
            testEngine = FakeEncryption(),
        )
        val original = k1.getOrCreateSecret("main_db")
        assertEquals(32, original.size)
        k1.close()

        // Instance 2 — cold start where the secret can't be decrypted. Under
        // PLAIN_TEXT this drops it from memoryCache; the guard must still detect
        // the entry exists (via protectionMap) and throw, NOT rotate.
        val k2 = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
            testEngine = AlwaysFailDecryptEngine(),
        )
        val ex = assertFailsWith<IllegalStateException> { k2.getOrCreateSecret("main_db") }
        assertTrue(
            ex.message?.contains("exists but could not be read back") == true,
            "must refuse to rotate the unreadable secret; was: ${ex.message}",
        )
        k2.close()

        // Instance 3 — vault healthy again: the ORIGINAL secret must be intact,
        // proving instance 2 did not silently overwrite it.
        val k3 = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
            testEngine = FakeEncryption(),
        )
        val recovered = k3.getOrCreateSecret("main_db")
        assertContentEquals(
            original, recovered,
            "secret must survive an unreadable cold-start session unrotated (no silent data loss)",
        )
        k3.close()
    }
}
