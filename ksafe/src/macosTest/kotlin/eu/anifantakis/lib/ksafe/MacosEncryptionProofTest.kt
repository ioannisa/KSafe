package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.get
import kotlinx.cinterop.reinterpret
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import platform.Foundation.NSData
import platform.Foundation.NSURL
import platform.Foundation.dataWithContentsOfURL
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Locks in: an encrypted write never lands the raw plaintext sentinel in the on-disk
 * DataStore file, while a `KSafeWriteMode.Plain` write does. Uses [FakeEncryption] (no
 * Keychain entitlements in the test runner) and a temp directory, not `~/Library`.
 */
@OptIn(ExperimentalForeignApi::class)
class MacosEncryptionProofTest {

    private val createdDirs = mutableListOf<String>()

    @AfterTest
    fun cleanup() {
        createdDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        createdDirs.clear()
    }

    private fun readDataStoreFile(directory: String, fileName: String): ByteArray? {
        val path = "$directory/eu_anifantakis_ksafe_datastore_$fileName.preferences_pb"
        val data: NSData = NSData.dataWithContentsOfURL(NSURL.fileURLWithPath(path))
            ?: return null

        val length = data.length.toInt()
        if (length == 0) return ByteArray(0)
        val ptr = data.bytes!!.reinterpret<UByteVar>()
        val out = ByteArray(length)
        for (i in 0 until length) out[i] = ptr[i].toByte()
        return out
    }

    @Test
    fun encryptedWriteDoesNotLeakPlaintextToDataStoreFile() = runTest {
        val fileName = MacosTestPaths.uniqueFileName("macosproofenc")
        val tempDir = MacosTestPaths.uniqueTempDir("macos-proof-enc")
        createdDirs += tempDir

        val ksafe = KSafe(
            fileName = fileName,
            directory = tempDir,
            testEngine = FakeEncryption(),
        )

        ksafe.put(KEY, SENTINEL) // put() defaults to encrypted
        delay(500)

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"), "encryption must round-trip")

        val raw = readDataStoreFile(tempDir, fileName)
        assertNotNull(raw, "DataStore file must exist for $fileName")
        assertFalse(
            raw.containsUtf8(SENTINEL),
            "plaintext '$SENTINEL' must NOT appear in the raw DataStore file " +
                "(size=${raw.size}); encryption plumbing has regressed",
        )
        ksafe.close()
    }

    @Test
    fun plainModeWriteDoesLeakPlaintextToDataStoreFile() = runTest {
        val fileName = MacosTestPaths.uniqueFileName("macosproofplain")
        val tempDir = MacosTestPaths.uniqueTempDir("macos-proof-plain")
        createdDirs += tempDir

        val ksafe = KSafe(
            fileName = fileName,
            directory = tempDir,
            testEngine = FakeEncryption(),
        )

        ksafe.put(KEY, SENTINEL, KSafeWriteMode.Plain)
        delay(500)

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"))

        val raw = readDataStoreFile(tempDir, fileName)
        assertNotNull(raw)
        assertTrue(
            raw.containsUtf8(SENTINEL),
            "KSafeWriteMode.Plain is expected to write plaintext to DataStore",
        )
        ksafe.close()
    }

    companion object {
        private const val SENTINEL = "KSAFE_PLAINTEXT_PROOF_SENTINEL_MACOS_QWERTY9876543210"
        private const val KEY = "proof_token"
    }
}
