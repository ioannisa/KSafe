package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.stringPreferencesKey
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStoreKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Gold-standard 2.0.0 → 2.1.0 data-survival test.
 *
 * Reads a **frozen, committed** DataStore preferences file produced in the
 * KSafe 2.0.0 on-disk layout — AES key at `ksafe_key_<alias>` (the 2.0.0 JVM
 * key location), value at `__ksafe_value_<alias>` (Base64 `IV‖ciphertext`) —
 * and proves 2.1.0 still decrypts it byte-for-byte, both when an OS secret
 * store is available (key migrates out of the file) and when it is not
 * (transparent fallback, key left in place).
 *
 * Unlike [JvmKeyVaultMigrationTest] (which synthesises the legacy state at
 * runtime), this binds against bytes checked into the repo, so a future change
 * to the key-storage format, AES-GCM framing, or migration logic that would
 * orphan real users' 2.0.0 data fails this test loudly.
 *
 * Fixture: `src/jvmTest/resources/fixtures/ksafe200.preferences_pb`.
 */
class Jvm200To210FixtureTest {

    private companion object {
        const val ALIAS = "greeting"
        const val PLAINTEXT = "ksafe-200-fixture-payload-7f3a"
        const val RESOURCE = "/fixtures/ksafe200.preferences_pb"
    }

    /** In-memory stand-in for an OS-backed vault (DPAPI/Keychain/Secret Service). */
    private class FakeOsVault : JvmKeyVault {
        val store = ConcurrentHashMap<String, ByteArray>()
        override val name = "FakeOsVault (fixture test)"
        override val isOsBacked = true
        override fun get(alias: String) = store[alias]?.copyOf()
        override fun put(alias: String, keyBytes: ByteArray) { store[alias] = keyBytes.copyOf() }
        override fun delete(alias: String) { store.remove(alias) }
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tmpDir = File(System.getProperty("java.io.tmpdir"), "ksafe_fx_${System.nanoTime()}")
        .apply { mkdirs() }

    @AfterTest
    fun tearDown() {
        scope.cancel()
        tmpDir.deleteRecursively()
    }

    /** Copies the committed 2.0.0 fixture to a fresh temp DataStore file. */
    private fun freshDataStoreFromFixture(): Pair<DataStore<Preferences>, File> {
        val bytes = Jvm200To210FixtureTest::class.java.getResourceAsStream(RESOURCE)
            ?.readBytes()
            ?: error("Missing test resource $RESOURCE — is jvmTest resources processing on?")
        val file = File(tmpDir, "ksafe200_${System.nanoTime()}.preferences_pb")
        file.writeBytes(bytes)
        return PreferenceDataStoreFactory.create(scope = scope) { file } to file
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun storedCiphertext(ds: DataStore<Preferences>): ByteArray {
        val prefs = runBlocking { ds.data.first() }
        // Sanity: the fixture really is in the 2.0.0 shape.
        assertNotNull(
            prefs[stringPreferencesKey("ksafe_key_$ALIAS")],
            "fixture must carry the 2.0.0 AES key at ksafe_key_$ALIAS",
        )
        val valueB64 = prefs[stringPreferencesKey("__ksafe_value_$ALIAS")]
        assertNotNull(valueB64, "fixture must carry the 2.0.0 encrypted value")
        return Base64.decode(valueB64)
    }

    @Test
    fun frozen2_0_0_data_decrypts_and_key_migrates_under2_1_0() {
        val (ds, _) = freshDataStoreFromFixture()
        val ciphertext = storedCiphertext(ds)

        val osVault = FakeOsVault()
        val engine = JvmSoftwareEncryption(
            dataStore = ds,
            vaultProvider = JvmKeyVaultProvider(ds, forced = osVault),
        )

        // The decisive assertion: frozen 2.0.0 ciphertext still decrypts.
        assertEquals(
            PLAINTEXT, String(engine.decrypt(ALIAS, ciphertext)),
            "2.0.0 ciphertext must decrypt unchanged under 2.1.0",
        )
        // Key migrated out of the plaintext file into the OS vault.
        assertNotNull(osVault.store[ALIAS], "key must migrate into the OS vault")
        assertNull(
            DataStoreKeyVault(ds).get(ALIAS),
            "legacy ksafe_key_ entry must be scrubbed after verified migration",
        )
    }

    @Test
    fun frozen2_0_0_decrypts_even_when_os_vault_holds_a_STALE_key() {
        // 2.0.0 -> 2.1.0 data-loss regression guard.
        //
        // The OS secret store (Keychain / DPAPI / Secret Service) is global
        // per-user and long-lived: it survives DataStore deletion, app-data
        // clear, reinstall, and mixed 2.0/2.1 runs. So on upgrade it can
        // already hold a DIFFERENT (stale, from a prior lifecycle) key under
        // the same `<file>:<alias>` while the REAL legacy key still sits in
        // the 2.0.0 DataStore. The legacy key is authoritative — it provably
        // encrypted this ciphertext — and must NOT be shadowed by the stale
        // OS key. The pre-fix code trusted the OS vault first and migrated
        // only when it was empty, so every encrypted value silently reset to
        // its default (plaintext values, needing no key, survived). This test
        // binds the *frozen real 2.0.0* bytes against a pre-populated (stale)
        // OS vault; it fails on the old logic and passes on legacy-first.
        val (ds, _) = freshDataStoreFromFixture()
        val ciphertext = storedCiphertext(ds)

        val staleKey = ByteArray(32) { 0x7B }
        val osVault = FakeOsVault().apply { store[ALIAS] = staleKey.copyOf() }

        val engine = JvmSoftwareEncryption(
            dataStore = ds,
            vaultProvider = JvmKeyVaultProvider(ds, forced = osVault),
        )

        assertEquals(
            PLAINTEXT, String(engine.decrypt(ALIAS, ciphertext)),
            "a stale OS-vault key must NOT shadow the authoritative legacy " +
                "key — frozen 2.0.0 data must still decrypt under 2.1.0",
        )
        // The stale OS key was overwritten with the real (legacy) key…
        val migrated = osVault.store[ALIAS]
        assertNotNull(migrated, "real key must be written into the OS vault")
        assertFalse(
            migrated.contentEquals(staleKey),
            "the stale OS-vault key must have been overwritten by the real one",
        )
        // …and the legacy copy scrubbed only after that.
        assertNull(
            DataStoreKeyVault(ds).get(ALIAS),
            "legacy ksafe_key_ entry must be scrubbed after authoritative migration",
        )
    }

    @Test
    fun frozen2_0_0_data_decrypts_when_no_os_store_fallback() {
        val (ds, _) = freshDataStoreFromFixture()
        val ciphertext = storedCiphertext(ds)

        // No OS store available → provider falls back to the legacy DataStore
        // vault; 2.0.0 data must still read and the key must stay put.
        System.setProperty("ksafe.jvm.keyVault", "software")
        try {
            val provider = JvmKeyVaultProvider(ds)
            assertEquals(provider.legacy, provider.active, "no OS store ⇒ legacy vault active")
            val engine = JvmSoftwareEncryption(dataStore = ds, vaultProvider = provider)
            assertEquals(PLAINTEXT, String(engine.decrypt(ALIAS, ciphertext)))
            assertTrue(
                DataStoreKeyVault(ds).get(ALIAS) != null,
                "fallback must keep the legacy key (nothing to migrate to)",
            )
        } finally {
            System.clearProperty("ksafe.jvm.keyVault")
        }
    }
}
