package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStoreKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Exercises the [JvmKeyVault] wiring and the KSafe ≤ 2.0 → OS-store migration
 * deterministically, using an in-memory fake vault so no real OS Keychain /
 * keyring is touched.
 */
class JvmKeyVaultMigrationTest {

    /** In-memory stand-in for an OS-backed vault. */
    private class FakeOsVault : JvmKeyVault {
        val store = ConcurrentHashMap<String, ByteArray>()
        override val name = "FakeOsVault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? = store[alias]?.copyOf()
        override fun put(alias: String, keyBytes: ByteArray) { store[alias] = keyBytes.copyOf() }
        override fun delete(alias: String) { store.remove(alias) }
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tmpDir = File(System.getProperty("java.io.tmpdir"), "ksafe_kv_${System.nanoTime()}")
        .apply { mkdirs() }
    private val dsFile = File(tmpDir, "kv.preferences_pb")
    private val dataStore: DataStore<Preferences> =
        PreferenceDataStoreFactory.create(scope = scope, produceFile = { dsFile })

    @AfterTest
    fun tearDown() {
        scope.cancel()
        tmpDir.deleteRecursively()
    }

    @Test
    fun legacyKey_isMigratedIntoOsVault_andRemovedFromDataStore() {
        val alias = "user:token"
        val legacy = DataStoreKeyVault(dataStore)
        val legacyKey = ByteArray(32) { it.toByte() }
        legacy.put(alias, legacyKey)

        val fake = FakeOsVault()
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = fake),
        )

        // Triggers getOrCreateSecretKey → migration path.
        val ct = engine.encrypt(alias, "hello".toByteArray())
        assertEquals("hello", String(engine.decrypt(alias, ct)))

        // Key moved into the OS vault using the *same* bytes (so older
        // ciphertext stays decryptable) and scrubbed from the plaintext file.
        assertContentEquals(legacyKey, fake.store[alias])
        assertNull(legacy.get(alias), "legacy DataStore entry must be removed after migration")
        assertEquals(fake.name, engine.keyVaultName)
    }

    @Test
    fun freshKey_isCreatedInOsVault_notInDataStore() {
        val alias = "fresh"
        val fake = FakeOsVault()
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = fake),
        )

        val ct = engine.encrypt(alias, "data".toByteArray())
        assertEquals("data", String(engine.decrypt(alias, ct)))

        assertNotNull(fake.store[alias], "new key must land in the OS vault")
        assertNull(DataStoreKeyVault(dataStore).get(alias), "new key must NOT touch the plaintext file")

        engine.deleteKey(alias)
        assertNull(fake.store[alias], "deleteKey must remove from the active vault")
    }

    @Test
    fun noOsStore_fallsBackToDataStore_explicitOptOut() {
        // `software` opt-out → provider must select the legacy DataStore vault.
        System.setProperty("ksafe.jvm.keyVault", "software")
        try {
            val provider = JvmKeyVaultProvider(dataStore)
            assertEquals(false, provider.active.isOsBacked)
            assertEquals(provider.legacy, provider.active)
        } finally {
            System.clearProperty("ksafe.jvm.keyVault")
        }
    }
}
