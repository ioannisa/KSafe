package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import java.io.File
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Proof-test for encryption on the JVM target.
 *
 * Exercises the production encryption path (no test engine injected — real
 * [JvmSoftwareEncryption] + AES-256-GCM runs) and then reads the raw bytes
 * of the underlying DataStore `.preferences_pb` file from disk. Asserts:
 *
 *  1. Encrypted writes: the plaintext sentinel does **not** appear anywhere
 *     in the file. The stored value is ciphertext, not the original string.
 *  2. Round-trip through KSafe still returns the original plaintext, i.e.
 *     encryption is sound and reversible.
 *  3. Baseline counter-test: a [KSafeWriteMode.Plain] write **does** leak
 *     the sentinel verbatim, which proves the negative assertion in (1) is
 *     meaningful (it is not just "the file is empty").
 *
 * These tests are also the regression guard against any future change that
 * might accidentally bypass encryption or write plaintext where ciphertext
 * is expected.
 */
class JvmEncryptionProofTest {

    private fun dataStoreFile(fileName: String): File {
        val homeDir = Paths.get(System.getProperty("user.home")).toFile()
        val baseDir = File(homeDir, ".eu_anifantakis_ksafe")
        return File(baseDir, "eu_anifantakis_ksafe_datastore_$fileName.preferences_pb")
    }

    @Test
    fun encryptedWriteDoesNotLeakPlaintextToDataStoreFile() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName)

        // Encrypted write (the default mode).
        ksafe.put(KEY, SENTINEL)
        delay(500) // let the DataStore flush settle

        // Sanity — encryption must be reversible.
        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"), "encryption must round-trip")

        val dataFile = dataStoreFile(fileName)
        assertTrue(dataFile.exists(), "DataStore file must exist: ${dataFile.absolutePath}")

        val raw = dataFile.readBytes()
        assertFalse(
            raw.containsUtf8(SENTINEL),
            "plaintext '$SENTINEL' must NOT appear in the raw DataStore file " +
                "(size=${raw.size}); this means KSafe has regressed and is writing unencrypted bytes"
        )
    }

    @Test
    fun plainModeWriteDoesLeakPlaintextToDataStoreFile() = runTest {
        // The positive baseline: a KSafeWriteMode.Plain write is expected to
        // store the sentinel verbatim. If this assertion ever fails, the raw
        // file-bytes search in `encryptedWriteDoesNotLeakPlaintextToDataStoreFile`
        // has become meaningless (both tests would pass even if writes never
        // happened), so we check it explicitly.
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName)

        ksafe.put(KEY, SENTINEL, KSafeWriteMode.Plain)
        delay(500)

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"))

        val raw = dataStoreFile(fileName).readBytes()
        assertTrue(
            raw.containsUtf8(SENTINEL),
            "KSafeWriteMode.Plain is expected to write plaintext to DataStore; " +
                "raw file must contain '$SENTINEL'"
        )
    }

    companion object {
        // A distinctive, high-entropy plaintext — picked so that the odds of
        // it appearing as a random substring of arbitrary ciphertext or
        // protobuf framing bytes are negligible.
        private const val SENTINEL = "KSAFE_PLAINTEXT_PROOF_SENTINEL_XYZABC_1234567890"
        private const val KEY = "proof_token"
    }
}
