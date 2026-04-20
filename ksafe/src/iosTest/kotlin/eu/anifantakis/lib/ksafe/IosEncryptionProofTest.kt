package eu.anifantakis.lib.ksafe

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.get
import kotlinx.cinterop.reinterpret
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import platform.Foundation.NSData
import platform.Foundation.NSDocumentDirectory
import platform.Foundation.NSFileManager
import platform.Foundation.NSURL
import platform.Foundation.NSUserDomainMask
import platform.Foundation.dataWithContentsOfURL
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Proof-test for encryption on iOS.
 *
 * **Test-engine note:** The Kotlin/Native test runner does not carry the
 * Keychain entitlement, so the production [IosKeychainEncryption] path
 * fails with `errSecMissingEntitlement` (-25291) — see [IosKeychainEncryptionTest]
 * for the coverage of that error path. To exercise KSafe's *write plumbing*
 * (the part that decides whether plaintext or ciphertext is written to the
 * DataStore file) we inject [FakeEncryption], whose XOR output is still not
 * the plaintext bytes. The real Keychain + CryptoKit round-trip is covered
 * by the iOS integration app and by `IosKeychainEncryptionTest`.
 *
 * What these tests do prove: an encrypted KSafe write never lands the raw
 * plaintext in the DataStore file. Anything that accidentally bypassed
 * encryption (e.g. a refactor that routed a `put()` through the plain path)
 * would immediately fail.
 */
class IosEncryptionProofTest {

    @OptIn(ExperimentalUuidApi::class)
    private fun uniqueFileName(): String =
        Uuid.random().toString().lowercase().filter { it in 'a'..'z' }.take(20)

    @OptIn(ExperimentalForeignApi::class)
    private fun readDataStoreFile(fileName: String): ByteArray? {
        val docDir: NSURL = NSFileManager.defaultManager.URLForDirectory(
            directory = NSDocumentDirectory,
            inDomain = NSUserDomainMask,
            appropriateForURL = null,
            create = false,
            error = null
        ) ?: return null
        val path = docDir.path!! + "/eu_anifantakis_ksafe_datastore_$fileName.preferences_pb"
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
        val fileName = uniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        ksafe.put(KEY, SENTINEL) // encrypted
        delay(500)

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"), "encryption must round-trip")

        val raw = readDataStoreFile(fileName)
        assertNotNull(raw, "DataStore file must exist for $fileName")
        assertFalse(
            raw.containsUtf8(SENTINEL),
            "plaintext '$SENTINEL' must NOT appear in the raw DataStore file " +
                "(size=${raw.size}); encryption plumbing has regressed"
        )
    }

    @Test
    fun plainModeWriteDoesLeakPlaintextToDataStoreFile() = runTest {
        val fileName = uniqueFileName()
        val ksafe = KSafe(fileName = fileName, testEngine = FakeEncryption())

        ksafe.put(KEY, SENTINEL, KSafeWriteMode.Plain)
        delay(500)

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"))

        val raw = readDataStoreFile(fileName)
        assertNotNull(raw)
        assertTrue(
            raw.containsUtf8(SENTINEL),
            "KSafeWriteMode.Plain is expected to write plaintext to DataStore"
        )
    }

    companion object {
        private const val SENTINEL = "KSAFE_PLAINTEXT_PROOF_SENTINEL_XYZABC_1234567890"
        private const val KEY = "proof_token"
    }
}
