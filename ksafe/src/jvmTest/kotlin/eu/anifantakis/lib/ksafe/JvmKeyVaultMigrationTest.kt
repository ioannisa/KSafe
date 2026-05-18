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

    // ── 2.0.0 → 2.1.0 data-survival ──────────────────────────────────────────
    // The thing users actually care about: data encrypted by 2.0.0 (AES key in
    // the DataStore file) must still decrypt after upgrading to 2.1.0, both
    // when an OS vault is available (key migrates) and when it is not
    // (transparent fallback).

    @Test
    fun ciphertextWrittenUnder2_0_0_stillDecryptsAfter2_1_0_keyMigration() {
        val alias = "user:token"
        val payload = "balance=4242;iban=GR16".toByteArray()

        // 2.0.0: software vault == legacy DataStore key location (ksafe_key_*).
        val v200 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = DataStoreKeyVault(dataStore)),
        )
        val ciphertextAtRest = v200.encrypt(alias, payload)
        val key200 = DataStoreKeyVault(dataStore).get(alias)
        assertNotNull(key200, "2.0.0 must persist the AES key in the DataStore file")

        // 2.1.0 upgrade: a fresh engine (new process) with an OS-backed vault
        // decrypts the SAME at-rest ciphertext written by 2.0.0.
        val osVault = FakeOsVault()
        val v210 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        )
        assertContentEquals(
            payload, v210.decrypt(alias, ciphertextAtRest),
            "2.0.0 ciphertext must still decrypt after the 2.1.0 upgrade",
        )
        assertContentEquals(key200, osVault.store[alias], "key migrated byte-for-byte into the OS vault")
        assertNull(DataStoreKeyVault(dataStore).get(alias), "plaintext key scrubbed from DataStore post-migration")
    }

    @Test
    fun ciphertextWrittenUnder2_0_0_stillDecryptsWhenNoOsStoreAvailable() {
        val alias = "settings:theme"
        val payload = "dark".toByteArray()

        val v200 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = DataStoreKeyVault(dataStore)),
        )
        val ciphertextAtRest = v200.encrypt(alias, payload)

        // 2.1.0 on a host with NO OS secret store → provider falls back to the
        // legacy DataStore vault; old data must still read and the key must NOT
        // be deleted (nothing to migrate to).
        System.setProperty("ksafe.jvm.keyVault", "software")
        try {
            val provider = JvmKeyVaultProvider(dataStore)
            assertEquals(provider.legacy, provider.active, "no OS store ⇒ legacy vault active")
            val v210 = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)
            assertContentEquals(payload, v210.decrypt(alias, ciphertextAtRest))
            assertNotNull(
                DataStoreKeyVault(dataStore).get(alias),
                "fallback must keep the legacy key in place (no OS store to move it to)",
            )
        } finally {
            System.clearProperty("ksafe.jvm.keyVault")
        }
    }
}
