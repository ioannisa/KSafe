package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.test.runTest
import java.io.File
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: on the JVM production path (real AES-256-GCM), an encrypted write never leaves its plaintext sentinel in the raw `.preferences_pb` file yet still round-trips, while a KSafeWriteMode.Plain write does leak it verbatim — proving the negative check is meaningful.
 */
class JvmEncryptionProofTest {

    private fun dataStoreFile(fileName: String): File {
        val homeDir = Paths.get(System.getProperty("user.home")).toFile()
        val baseDir = File(homeDir, ".eu_anifantakis_ksafe")
        return File(baseDir, "eu_anifantakis_ksafe_datastore_$fileName.preferences_pb")
    }

    /**
     * Waits in REAL time until [file] exists with a stable size. runTest's `delay` is virtual, but the
     * write flushes on a background coroutine, so `Thread.sleep` is the real settle barrier.
     */
    private fun awaitFileReady(file: File, timeoutMs: Long = 15_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastLen = -1L
        while (System.currentTimeMillis() < deadline) {
            if (file.exists()) {
                val len = file.length()
                if (len > 0L && len == lastLen) return
                lastLen = len
            }
            Thread.sleep(50)
        }
    }

    @Test
    fun encryptedWriteDoesNotLeakPlaintextToDataStoreFile() = runTest {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName)

        ksafe.put(KEY, SENTINEL)
        awaitFileReady(dataStoreFile(fileName))

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
        // Positive baseline: a Plain write must store the sentinel verbatim, else the raw-bytes search
        // in the encrypted test would be meaningless (both would pass even if writes never happened).
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val ksafe = KSafe(fileName = fileName)

        ksafe.put(KEY, SENTINEL, KSafeWriteMode.Plain)
        awaitFileReady(dataStoreFile(fileName))

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"))

        val raw = dataStoreFile(fileName).readBytes()
        assertTrue(
            raw.containsUtf8(SENTINEL),
            "KSafeWriteMode.Plain is expected to write plaintext to DataStore; " +
                "raw file must contain '$SENTINEL'"
        )
    }

    companion object {
        // High-entropy sentinel: negligible odds of appearing as a random substring of ciphertext or protobuf framing.
        private const val SENTINEL = "KSAFE_PLAINTEXT_PROOF_SENTINEL_XYZABC_1234567890"
        private const val KEY = "proof_token"
    }
}
