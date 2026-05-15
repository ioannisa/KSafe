package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Integration test that exercises the **real** OS secret store
 * (Windows DPAPI / macOS Keychain / Linux Secret Service).
 *
 * It is opt-in: it only runs when the `KSAFE_KEYVAULT_IT` environment variable
 * is set (the keyvault CI jobs set it). Locally and in the normal `jvmTest`
 * run it is a no-op, so it never prompts for Keychain access or pollutes the
 * developer keyring. The CI jobs are responsible for providing a working
 * keyring (Linux: gnome-keyring under a dbus session; macOS: a dedicated
 * unlocked keychain).
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
        if (!provider.active.isOsBacked) return // covered by the assertion above

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
}
