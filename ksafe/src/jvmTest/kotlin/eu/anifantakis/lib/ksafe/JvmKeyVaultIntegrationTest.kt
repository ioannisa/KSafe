package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStoreKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: the real OS secret store (DPAPI / Keychain / Secret Service) is selected, round-trips keys, and wins over stale or legacy entries — opt-in via the KSAFE_KEYVAULT_IT env var so local runs never touch the developer keyring.
 */
class JvmKeyVaultIntegrationTest {

    private val enabled = !System.getenv("KSAFE_KEYVAULT_IT").isNullOrBlank()
    private val os = System.getProperty("os.name").orEmpty().lowercase()

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tmpDir = File(System.getProperty("java.io.tmpdir"), "ksafe_kv_it_${System.nanoTime()}")
        .apply { mkdirs() }
    private val dataStore: DataStore<Preferences> = PreferenceDataStoreFactory.create(
        scope = scope,
        produceFile = { File(tmpDir, "kv.preferences_pb") },
    )

    @AfterTest
    fun tearDown() {
        scope.cancel()
        tmpDir.deleteRecursively()
    }

    private fun expectedVaultMarker(): String = when {
        os.contains("win") -> "DPAPI"
        os.contains("mac") || os.contains("darwin") -> "Keychain"
        else -> "Secret Service"
    }

    @Test
    fun realOsVault_isSelected_andRoundTrips_andDoesNotTouchTheFile() {
        if (!enabled) {
            println("[skip] JvmKeyVaultIntegrationTest — set KSAFE_KEYVAULT_IT to run")
            return
        }

        val provider = JvmKeyVaultProvider(dataStore)
        assertTrue(
            provider.active.isOsBacked,
            "expected an OS-backed vault but got '${provider.active.name}'. " +
                "Is the keyring/keychain set up in this CI job?",
        )
        assertTrue(
            provider.active.name.contains(expectedVaultMarker()),
            "expected the $os vault ('${expectedVaultMarker()}') but got '${provider.active.name}'",
        )

        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)
        val alias = "ksafe_it_${System.nanoTime()}"
        try {
            val ct = engine.encrypt(alias, "integration-secret".toByteArray())
            assertEquals("integration-secret", String(engine.decrypt(alias, ct)))

            assertNotNull(provider.active.get(alias), "key must be in the OS store")
            assertNull(provider.legacy.get(alias), "key must NOT be written to the plaintext file")
        } finally {
            engine.deleteKey(alias)
            assertNull(provider.active.get(alias), "deleteKey must purge the OS store entry")
        }
    }

    @Test
    fun legacyFileKey_migratesIntoRealOsVault() {
        if (!enabled) return

        val provider = JvmKeyVaultProvider(dataStore)
        if (!provider.active.isOsBacked) return

        val alias = "ksafe_it_mig_${System.nanoTime()}"
        val legacyKey = ByteArray(32) { (it * 7).toByte() }
        provider.legacy.put(alias, legacyKey)

        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)
        try {
            val ct = engine.encrypt(alias, "migrate-me".toByteArray())
            assertEquals("migrate-me", String(engine.decrypt(alias, ct)))

            assertNotNull(provider.active.get(alias), "legacy key must be migrated into the OS store")
            assertNull(provider.legacy.get(alias), "legacy file entry must be removed after migration")
        } finally {
            engine.deleteKey(alias)
            assertNull(provider.active.get(alias))
        }
    }

    /**
     * Dirty precondition: the OS store already holds a stale key for the alias;
     * the legacy DataStore key that encrypted the data must win and overwrite it.
     */
    @Test
    fun legacyData_survivesUpgrade_evenWhenRealOsStoreHoldsAStaleKey() {
        if (!enabled) return

        val provider = JvmKeyVaultProvider(dataStore)
        if (!provider.active.isOsBacked) return

        val alias = "ksafe_it_stale_${System.nanoTime()}"
        val payload = "iban=GR1601;balance=4242".toByteArray()
        try {
            val v200 = JvmSoftwareEncryption(
                dataStore = dataStore,
                vaultProvider = JvmKeyVaultProvider(dataStore, forced = DataStoreKeyVault(dataStore)),
            )
            val ciphertextAtRest = v200.encrypt(alias, payload)
            val legacyKey = DataStoreKeyVault(dataStore).get(alias)
            assertNotNull(legacyKey, "2.0.0 must persist the AES key in the DataStore file")

            // Seed the real OS store with a mismatched key before the upgrade.
            provider.active.put(alias, ByteArray(32) { 0x5A })

            val v210 = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)
            assertContentEquals(
                payload, v210.decrypt(alias, ciphertextAtRest),
                "2.0.0 data must survive upgrade even when the real OS store " +
                    "already held a stale key for this alias",
            )
            assertContentEquals(
                legacyKey, provider.active.get(alias),
                "the stale real-OS-store key must be overwritten with the real one",
            )
            assertNull(
                DataStoreKeyVault(dataStore).get(alias),
                "legacy plaintext key scrubbed only after verified migration",
            )
        } finally {
            JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)
                .deleteKey(alias)
            assertNull(provider.active.get(alias), "real OS-store entry purged on cleanup")
        }
    }
}
