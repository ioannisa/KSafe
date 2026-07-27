package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in the `isEncryptionOperational` preflight on JVM: when an OS secret store EXISTS but fails
 * its construction self-test (locked Keychain/keyring, headless), KSafe refuses to mint keys so
 * every encrypted op throws — protectionInfo must report that as NON-operational, distinct from the
 * "no OS vault → software fallback" case which stays operational (weaker, but it encrypts fine).
 */
class JvmProtectionInfoDegradedTest {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tmpDir = File(System.getProperty("java.io.tmpdir"), "ksafe_pi_${System.nanoTime()}").apply { mkdirs() }
    private fun newDataStore(): DataStore<Preferences> = PreferenceDataStoreFactory.create(
        scope = scope,
        produceFile = { File(tmpDir, "pi_${System.nanoTime()}.preferences_pb") },
    )

    @AfterTest
    fun tearDown() {
        scope.cancel()
        tmpDir.deleteRecursively()
    }

    /** An OS vault that always fails its self-test: the canary read-back returns null. */
    private class FailingSelfTestVault : JvmKeyVault {
        override val name = "failing-os-vault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? = null
        override fun put(alias: String, keyBytes: ByteArray) { /* swallow the canary */ }
        override fun delete(alias: String) { /* no-op */ }
    }

    @Test
    fun protectionInfo_isNonOperational_whenOsVaultSelfTestFails() {
        // jvmTest sets -Dksafe.jvm.keyVault=software; that opt-out would short-circuit pick() before
        // it ever self-tests our candidate (and would make jvmProtectionInfo report opted-out).
        // Clear it for the scope of this test so the self-test-failure path is exercised.
        val prop = "ksafe.jvm.keyVault"
        val saved = System.getProperty(prop)
        System.clearProperty(prop)
        try {
            val ds = newDataStore()
            val provider = JvmKeyVaultProvider(dataStore = ds, osCandidateForTest = FailingSelfTestVault())
            val engine = JvmSoftwareEncryption(dataStore = ds, vaultProvider = provider)
            val ksafe = KSafe(fileName = JvmKSafeTest.generateUniqueFileName(), testEngine = engine)

            val info = ksafe.protectionInfo
            assertTrue(
                info.notes.contains("jvm_os_vault_degraded"),
                "a failed OS-vault self-test must surface the degraded note; was: ${info.notes}",
            )
            assertFalse(
                info.isEncryptionOperational,
                "with the OS vault unreachable every encrypted op throws — the preflight must report NON-operational",
            )
            ksafe.close()
        } finally {
            if (saved != null) System.setProperty(prop, saved) else System.clearProperty(prop)
        }
    }

    @Test
    fun protectionInfo_staysOperational_underSoftwareFallback() {
        // The jvmTest default (-Dksafe.jvm.keyVault=software) selects the software vault: weaker than
        // intended but fully operational — it must NOT be flagged non-operational.
        val ds = newDataStore()
        val engine = JvmSoftwareEncryption(dataStore = ds)
        val ksafe = KSafe(fileName = JvmKSafeTest.generateUniqueFileName(), testEngine = engine)

        val info = ksafe.protectionInfo
        assertTrue(
            info.isEncryptionOperational,
            "a software fallback / opt-out encrypts fine and must stay operational; notes=${info.notes}",
        )
        ksafe.close()
    }
}
