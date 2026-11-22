package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Locks in: a store restored without its Keystore keys (Auto Backup, device-to-device transfer)
 * has its encrypted entries reclaimed by the startup sweep on every tier, including the
 * software-DEK `DEFAULT` tier, whose master key startup used to re-create before the sweep ran.
 */
@RunWith(AndroidJUnit4::class)
class AndroidRestoreWithoutKeysTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private fun keystore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun aliases(): Set<String> = keystore().aliases().toList().toSet()

    private fun open(file: String): KSafe = KSafe(context, fileName = file)

    /** Writes "token" with [mode], then deletes every Keystore key that session minted: the store
     *  file survives and the keys do not, as after a restore onto a new device. */
    private suspend fun restoreWithoutKeys(mode: KSafeWriteMode): String {
        val file = "restore_${System.nanoTime()}"
        val before = aliases()
        val first = open(file)
        first.put("token", "abc123", mode)
        assertEquals("abc123", first.get("token", ""), "premise: the token round-trips")
        first.close()

        val minted = aliases() - before
        assertTrue(minted.isNotEmpty(), "premise: the first session minted Keystore keys")
        val ks = keystore()
        minted.forEach { ks.deleteEntry(it) }
        return file
    }

    private suspend fun assertReclaimedAndRecoverable(label: String, mode: KSafeWriteMode) {
        val file = restoreWithoutKeys(mode)

        val restored = open(file)
        assertEquals("", restored.get("token", ""), "$label: the unreadable token reads as the default")
        val reclaimed = withTimeoutOrNull(15_000) {
            while (restored.getKeyInfo("token") != null) delay(50)
            true
        } ?: false
        assertTrue(reclaimed, "$label: the startup sweep must reclaim an entry whose key is gone")

        restored.put("token", "def456", mode)
        assertEquals("def456", restored.get("token", ""), "$label: a fresh write must read back")
        restored.close()

        val relaunched = open(file)
        try {
            assertEquals("def456", relaunched.get("token", ""), "$label: a fresh write must survive a restart")
            assertNotNull(relaunched.getKeyInfo("token"), "$label: the sweep must keep a readable entry")
        } finally {
            relaunched.clearAll()
            relaunched.close()
        }
    }

    @Test
    fun defaultTier_softwareDek_isReclaimed() = runBlocking {
        assertReclaimedAndRecoverable("DEFAULT", KSafeWriteMode.Encrypted())
    }

    @Test
    fun strictDefault_isReclaimed() = runBlocking {
        assertReclaimedAndRecoverable(
            "DEFAULT + requireUnlockedDevice",
            KSafeWriteMode.Encrypted(requireUnlockedDevice = true),
        )
    }

    @Test
    fun hardwareIsolated_isReclaimed() = runBlocking {
        assertReclaimedAndRecoverable(
            "HARDWARE_ISOLATED",
            KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED),
        )
    }
}
