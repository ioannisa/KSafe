package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Locks in: getOrCreateSecret never silently rotates. An existing-but-unreadable secret — key
 * invalidated, vault down, corrupt ciphertext — throws instead of minting a replacement, which
 * would permanently orphan everything encrypted under the old one, such as a SQLCipher DB.
 */
class JvmGetOrCreateSecretTest {

    /** XOR engine whose `decrypt` throws (as if corrupt) while [failDecrypt] is set. */
    private class ToggleEngine : KSafeEncryption {
        @Volatile var failDecrypt = false
        private val xor = FakeEncryption()

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray = xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray {
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

        val original = ksafe.getOrCreateSecret("main_db")
        assertEquals(32, original.size)

        // Still on disk, but no longer decryptable: key invalidated, or the vault is down.
        engine.failDecrypt = true

        val ex = assertFailsWith<IllegalStateException> {
            ksafe.getOrCreateSecret("main_db")
        }
        assertTrue(
            ex.message?.contains("exists but could not be read back") == true,
            "must surface the unreadable-secret condition rather than rotate; was: ${ex.message}",
        )

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
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        ksafe.put("unrelated", "value")

        val secret = ksafe.getOrCreateSecret("brand_new_db")
        assertEquals(32, secret.size, "absent secret must still be generated")

        ksafe.close()
    }

    @Test
    fun malformedBase64InTheSecretSlot_throwsTheDocumentedIse_andIsNotOverwritten() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        // The reserved slot decrypts fine but holds junk that is not Base64. The contract keeps
        // IllegalArgumentException for caller input, so an unreadable secret surfaces as ISE.
        ksafe.put("ksafe_secret_main_db", "not base64!!", KSafeWriteMode.Encrypted())

        val ex = assertFailsWith<IllegalStateException> { ksafe.getOrCreateSecret("main_db") }
        assertTrue(
            ex.message?.contains("not valid Base64") == true,
            "must surface the malformed slot as the documented unreadable-secret failure; was: ${ex.message}",
        )
        assertEquals(
            "not base64!!", ksafe.get("ksafe_secret_main_db", ""),
            "the malformed slot must be preserved for inspection, never overwritten",
        )

        ksafe.close()
    }

    @Test
    fun malformedLegacySecret_isNeverCopiedForwardToTheCanonicalSlot() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        // A special-char key routes through the legacy '_'-collapsed slot on first read.
        ksafe.put("ksafe_secret_my_db", "@@definitely-not-base64@@", KSafeWriteMode.Encrypted())

        assertFailsWith<IllegalStateException> { ksafe.getOrCreateSecret("my.db") }
        val canonicalSlot = "ksafe_secretx_" + "my.db".encodeToByteArray()
            .joinToString("") { b -> ((b.toInt() and 0xff).toString(16).padStart(2, '0')) }
        assertEquals(
            "", ksafe.get(canonicalSlot, ""),
            "a malformed legacy value must not be migrated into the canonical slot",
        )

        ksafe.close()
    }

    /** XOR engine whose `decrypt` always throws, as if the backing key were invalidated. */
    private class AlwaysFailDecryptEngine : KSafeEncryption {
        private val xor = FakeEncryption()
        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray = xor.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice)

        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray =
            throw IllegalStateException("KSafe: simulated unreadable secret (key invalidated)")

        override fun deleteKey(identifier: String) { /* no-op */ }
    }

    @Test
    fun underPlainTextPolicy_unreadableSecretOnColdStart_throwsInsteadOfRotating() = runTest {
        // Under PLAIN_TEXT a secret that fails cold-start decrypt is dropped from memoryCache, so
        // the never-rotate guard has to detect existence via protectionMap, which is on disk
        // regardless of decryptability; memoryCache alone would look absent and rotate.
        val fileName = JvmKSafeTest.generateUniqueFileName()

        val k1 = KSafe(
            fileName = fileName,
            memoryPolicy = KSafeMemoryPolicy.PLAIN_TEXT,
            testEngine = FakeEncryption(),
        )
        val original = k1.getOrCreateSecret("main_db")
        assertEquals(32, original.size)
        k1.close()

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

        // Vault healthy again, so k2 had better not have overwritten anything.
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
