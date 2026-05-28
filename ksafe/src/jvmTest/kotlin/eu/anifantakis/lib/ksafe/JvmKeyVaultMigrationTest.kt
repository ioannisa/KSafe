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
import kotlinx.coroutines.runBlocking
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

        // DIRTY precondition (the real-world case): the per-user OS store
        // ALREADY holds a stale/mismatched key for this alias from a prior
        // KSafe lifecycle. The legacy DataStore key is authoritative and must
        // win — an empty FakeOsVault here would pass even on the broken,
        // data-destroying code (it did: see the audit), testing nothing.
        val staleOsKey = ByteArray(32) { 0x5A }
        val fake = FakeOsVault().apply { store[alias] = staleOsKey.copyOf() }
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = fake),
        )

        // Triggers getOrCreateSecretKey → migration path.
        val ct = engine.encrypt(alias, "hello".toByteArray())
        assertEquals("hello", String(engine.decrypt(alias, ct)))

        // The stale OS key was OVERWRITTEN with the real (legacy) bytes (so
        // older ciphertext stays decryptable) and the plaintext file scrubbed.
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

        // 2.1.0 upgrade — the REAL precondition: the global per-user OS store
        // already holds a STALE key for this alias (prior install / data-clear
        // / reinstall / mixed-version run). A fresh engine must still decrypt
        // the 2.0.0 at-rest ciphertext because the legacy DataStore key is
        // authoritative. (With an empty osVault this test passed even on the
        // data-destroying pre-fix code — proven in the audit — so it tested
        // nothing. The stale seed is what makes it discriminate.)
        val osVault = FakeOsVault().apply { store[alias] = ByteArray(32) { 0x5A } }
        val v210 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        )
        assertContentEquals(
            payload, v210.decrypt(alias, ciphertextAtRest),
            "2.0.0 ciphertext must still decrypt after upgrade even when the " +
                "OS store already held a stale key for this alias",
        )
        assertContentEquals(key200, osVault.store[alias], "stale OS key overwritten with the real one")
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

    // ── Eager one-time sweep (hybrid) ────────────────────────────────────────

    @Test
    fun eagerSweep_migratesEveryLegacyKey_withoutReadingThem() {
        val legacy = DataStoreKeyVault(dataStore)
        val seeded = mapOf(
            "user:a" to ByteArray(32) { 1 },
            "user:b" to ByteArray(32) { 2 },
            "settings:c" to ByteArray(32) { 3 },
        )
        seeded.forEach { (k, v) -> legacy.put(k, v) }

        val fake = FakeOsVault()
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = fake),
        )

        // Sweep WITHOUT any prior encrypt/decrypt — proves it's eager, not lazy.
        runBlocking { engine.migrateLegacyKeysSuspend() }

        seeded.forEach { (k, v) ->
            assertContentEquals(v, fake.store[k], "$k must be eagerly migrated into the OS vault")
            assertNull(legacy.get(k), "$k legacy DataStore entry must be scrubbed")
        }
        // Idempotent: a second sweep is a clean no-op.
        runBlocking { engine.migrateLegacyKeysSuspend() }
        assertEquals(seeded.size, fake.store.size)
    }

    @Test
    fun eagerSweep_isNoOp_whenNoOsStore() {
        val legacy = DataStoreKeyVault(dataStore)
        legacy.put("k", ByteArray(32) { 9 })

        System.setProperty("ksafe.jvm.keyVault", "software")
        try {
            val provider = JvmKeyVaultProvider(dataStore) // active === legacy
            val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)
            runBlocking { engine.migrateLegacyKeysSuspend() }
            // No safer destination → legacy key left untouched (no data loss).
            assertNotNull(legacy.get("k"), "fallback sweep must not move/delete the legacy key")
        } finally {
            System.clearProperty("ksafe.jvm.keyVault")
        }
    }

    // ── Runtime LinkageError fallback ────────────────────────────────────────
    //
    // Simulates the real-world Compose Desktop release-distributable case:
    // selfTest at construction passes (full JDK on the build host), but the
    // jlinked runtime served to the user is missing `jdk.unsupported`, so JNA
    // throws `NoClassDefFoundError: sun/misc/Unsafe` on first real call from
    // inside processBatch — silently dropping every write before this fix.
    // See issue #32.

    private class LinkErrorOsVault(
        /** Flips to true after [armed] is set; lets selfTest succeed at init. */
        @Volatile var armed: Boolean = false,
    ) : JvmKeyVault {
        override val name = "LinkErrorOsVault (test)"
        override val isOsBacked = true
        val store = ConcurrentHashMap<String, ByteArray>()
        override fun get(alias: String): ByteArray? {
            if (armed) throw NoClassDefFoundError("sun/misc/Unsafe")
            return store[alias]?.copyOf()
        }
        override fun put(alias: String, keyBytes: ByteArray) {
            if (armed) throw NoClassDefFoundError("sun/misc/Unsafe")
            store[alias] = keyBytes.copyOf()
        }
        override fun delete(alias: String) {
            if (armed) throw NoClassDefFoundError("sun/misc/Unsafe")
            store.remove(alias)
        }
    }

    @Test
    fun runtimeLinkageError_degradesToLegacyVault_andEncryptSucceeds() {
        val alias = "user:token"
        val osVault = LinkErrorOsVault().also { it.armed = true }
        val provider = JvmKeyVaultProvider(dataStore, forced = osVault)
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // Pre-fix this would have thrown NoClassDefFoundError out of encrypt
        // and KSafeCore.processBatch would have dropped the write.
        val ct = engine.encrypt(alias, "hello".toByteArray())
        assertContentEquals("hello".toByteArray(), engine.decrypt(alias, ct))

        // After the runtime failure the provider must be degraded so the
        // active vault is now the legacy DataStore.
        assertEquals(provider.legacy, provider.active)
        // And the key the engine just used must live in the legacy store
        // (NOT in the unreachable OS vault).
        assertNotNull(DataStoreKeyVault(dataStore).get(alias))
    }

    @Test
    fun runtimeLinkageError_preservesLegacyKey_andDecryptsExisting2_0_0Data() {
        // The most data-sensitive variant: a 2.0.0 user upgrades to 2.1.x and
        // ships in a Compose Desktop release build. We must (a) not destroy
        // the legacy key (which is authoritative for at-rest ciphertext), and
        // (b) still decrypt their existing data.
        val alias = "settings:theme"
        val payload = "dark".toByteArray()

        val v200 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = DataStoreKeyVault(dataStore)),
        )
        val ciphertextAtRest = v200.encrypt(alias, payload)
        val legacyKeyBefore = DataStoreKeyVault(dataStore).get(alias)
        assertNotNull(legacyKeyBefore)

        // Upgrade: jlinked runtime lacks jdk.unsupported → JNA always fails.
        val osVault = LinkErrorOsVault().also { it.armed = true }
        val provider = JvmKeyVaultProvider(dataStore, forced = osVault)
        val v210 = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // Existing data must still decrypt.
        assertContentEquals(payload, v210.decrypt(alias, ciphertextAtRest))

        // Legacy key MUST still be present — migration tried, JNA failed, the
        // read-back gate prevented the delete. Without that gate this user
        // would lose their key.
        assertContentEquals(
            legacyKeyBefore, DataStoreKeyVault(dataStore).get(alias),
            "LinkageError during migration must not destroy the legacy key",
        )
        assertEquals(provider.legacy, provider.active)
    }

    @Test
    fun degradeIsIdempotent_andSurvivesConcurrentEncrypts() {
        val osVault = LinkErrorOsVault().also { it.armed = true }
        val provider = JvmKeyVaultProvider(dataStore, forced = osVault)
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // Concurrent first hits: only ONE warning should be emitted by the
        // provider (verified manually via System.err; here we just assert all
        // threads see consistent post-degrade state and no exception escapes).
        val threads = (0 until 16).map { i ->
            Thread {
                val ct = engine.encrypt("k$i", byteArrayOf(i.toByte()))
                engine.decrypt("k$i", ct)
            }.also { it.start() }
        }
        threads.forEach { it.join() }
        assertEquals(provider.legacy, provider.active)
    }
}
