package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Proof-test for encryption on the Android target.
 *
 * Runs on a real device/emulator (instrumented), through the production
 * [KSafe] path — no test engine injected, so AES-256-GCM via the real
 * Android Keystore actually runs. After each write we read the raw bytes
 * of the underlying DataStore `.preferences_pb` file from the app's
 * private `files/datastore/` directory and assert:
 *
 *  1. Encrypted writes: the plaintext sentinel does **not** appear in the
 *     file — only the Base64 ciphertext does.
 *  2. Round-trip still returns the original plaintext.
 *  3. Baseline counter-test: a [KSafeWriteMode.Plain] write **does** leak
 *     the sentinel, confirming the negative assertion is meaningful.
 */
@RunWith(AndroidJUnit4::class)
class AndroidEncryptionProofTest {

    @OptIn(ExperimentalUuidApi::class)
    private fun uniqueFileName(): String =
        Uuid.random().toString().lowercase().filter { it in 'a'..'z' }.take(20)

    private fun dataStoreFile(context: Context, fileName: String): File {
        // DataStore-Preferences writes under filesDir/datastore/<name>.preferences_pb
        val storeName = "eu_anifantakis_ksafe_datastore_$fileName"
        return File(File(context.filesDir, "datastore"), "$storeName.preferences_pb")
    }

    @Test
    fun encryptedWriteDoesNotLeakPlaintextToDataStoreFile() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val fileName = uniqueFileName()
        val ksafe = KSafe(context, fileName)

        ksafe.put(KEY, SENTINEL) // encrypted by default
        delay(500)

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"), "encryption must round-trip")

        val dataFile = dataStoreFile(context, fileName)
        assertTrue(dataFile.exists(), "DataStore file must exist: ${dataFile.absolutePath}")

        val raw = dataFile.readBytes()
        assertFalse(
            raw.containsUtf8(SENTINEL),
            "plaintext '$SENTINEL' must NOT appear in the raw DataStore file " +
                "(size=${raw.size}); KSafe appears to have written unencrypted bytes"
        )
    }

    @Test
    fun plainModeWriteDoesLeakPlaintextToDataStoreFile() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val fileName = uniqueFileName()
        val ksafe = KSafe(context, fileName)

        ksafe.put(KEY, SENTINEL, KSafeWriteMode.Plain)
        delay(500)

        assertEquals(SENTINEL, ksafe.get(KEY, "DEFAULT"))

        val raw = dataStoreFile(context, fileName).readBytes()
        assertTrue(
            raw.containsUtf8(SENTINEL),
            "KSafeWriteMode.Plain is expected to write plaintext to DataStore; " +
                "raw file must contain '$SENTINEL'"
        )
    }

    companion object {
        private const val SENTINEL = "KSAFE_PLAINTEXT_PROOF_SENTINEL_XYZABC_1234567890"
        private const val KEY = "proof_token"
    }
}

/**
 * Inlined copy of the [containsUtf8] helper (the commonTest version isn't
 * visible from `androidInstrumentedTest`, which is a sibling source set).
 */
private fun ByteArray.containsUtf8(needle: String): Boolean {
    val needleBytes = needle.encodeToByteArray()
    if (needleBytes.isEmpty()) return true
    if (needleBytes.size > this.size) return false
    outer@ for (i in 0..(this.size - needleBytes.size)) {
        for (j in needleBytes.indices) {
            if (this[i + j] != needleBytes[j]) continue@outer
        }
        return true
    }
    return false
}
