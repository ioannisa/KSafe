package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: clearAll() sweeps this safe's .preferences_pb.corrupt-* quarantine copies (and live .ksafe fallback files), while leaving a sibling safe's files in the same directory untouched.
 */
class JvmClearAllCorruptFileTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_corrupt_${System.nanoTime()}")
        .apply { mkdirs() }

    @AfterTest
    fun tearDown() {
        tmp.deleteRecursively()
    }

    private class IdentityEngine : KSafeEncryption {
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray = data
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun clearAll_deletesProtobufCorruptQuarantineCopies_butNotSiblingSafes() {
        val base = "eu_anifantakis_ksafe_datastore_wipe"
        // The DataStore corruption handler names quarantine copies like this.
        val ourCorrupt = File(tmp, "$base.preferences_pb.corrupt-1700000000000")
            .apply { writeText("recoverable-ciphertext") }
        // A DIFFERENT safe living in the same directory — must NOT be touched.
        val siblingCorrupt = File(tmp, "eu_anifantakis_ksafe_datastore_other.preferences_pb.corrupt-1700000000000")
            .apply { writeText("other-safe-ciphertext") }

        val ksafe = KSafe(fileName = "wipe", baseDir = tmp, testEngine = IdentityEngine())
        try {
            runBlocking {
                ksafe.put("k", "v")
                ksafe.clearAll()
            }
        } finally {
            ksafe.close()
        }

        assertFalse(
            ourCorrupt.exists(),
            "clearAll() must delete this safe's <base>.preferences_pb.corrupt-* quarantine copy",
        )
        assertTrue(
            siblingCorrupt.exists(),
            "clearAll() must NOT touch a different safe's corrupt quarantine copy in the same dir",
        )
    }

    @Test
    fun clearAll_deletesLiveResidualFallbackFiles_butNotSiblingSafes() {
        // A LIVE <base>.ksafe.json (ciphertext) and <base>.ksafe-keys.json (plaintext
        // AES key) can linger in the OS-backed store's directory; clearAll() must wipe
        // those too, while sparing a different safe's files.
        val base = "eu_anifantakis_ksafe_datastore_wipe"
        val liveJson = File(tmp, "$base.ksafe.json").apply { writeText("residual-ciphertext") }
        val liveKeys = File(tmp, "$base.ksafe-keys.json").apply { writeText("residual-plaintext-key") }
        val siblingKeys = File(tmp, "eu_anifantakis_ksafe_datastore_other.ksafe-keys.json").apply { writeText("other-safe-key") }

        val ksafe = KSafe(fileName = "wipe", baseDir = tmp, testEngine = IdentityEngine())
        try {
            runBlocking {
                ksafe.put("k", "v")
                ksafe.clearAll()
            }
        } finally {
            ksafe.close()
        }

        assertFalse(liveJson.exists(), "clearAll() must delete the live <base>.ksafe.json (residual ciphertext)")
        assertFalse(liveKeys.exists(), "clearAll() must delete the live <base>.ksafe-keys.json (residual plaintext key)")
        assertTrue(siblingKeys.exists(), "clearAll() must NOT touch a different safe's fallback key file")
    }
}
