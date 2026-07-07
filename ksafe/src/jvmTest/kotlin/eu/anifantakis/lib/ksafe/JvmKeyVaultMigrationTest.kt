package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStoreKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.keyvault.DEFAULT_JVM_NAMESPACE
import eu.anifantakis.lib.ksafe.internal.keyvault.legacyDerivedJvmNamespace
import eu.anifantakis.lib.ksafe.internal.keyvault.legacyFallbackNamespaces
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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Locks in: [JvmKeyVault] wiring and legacy-key → OS-store migration, via an in-memory fake vault. */
class JvmKeyVaultMigrationTest {

    @Test
    fun legacyFallbackNamespaces_probesBothDerivedAndSharedWhenExplicitAppNamespaceSet() {
        // An explicit appNamespace must probe BOTH legacy locations — the derived namespace
        // first, then the shared default — since either may hold the keys.
        assertEquals(listOf(DEFAULT_JVM_NAMESPACE), legacyFallbackNamespaces("myapp", derivedNamespace = null))
        assertEquals(
            listOf("myapp", DEFAULT_JVM_NAMESPACE),
            legacyFallbackNamespaces("com.example.app", derivedNamespace = "myapp"),
        )
    }

    @Test
    fun legacyFallbackNamespaces_probesDerivedWhenOnDefaultNamespace() {
        // On the shared default, the only fallback is the launcher-derived namespace.
        assertEquals(listOf("derived-ns"), legacyFallbackNamespaces(DEFAULT_JVM_NAMESPACE, derivedNamespace = "derived-ns"))
        // Nothing to probe when there is no derived namespace, or it equals the current one.
        assertEquals(emptyList<String>(), legacyFallbackNamespaces(DEFAULT_JVM_NAMESPACE, derivedNamespace = null))
        assertEquals(emptyList<String>(), legacyFallbackNamespaces(DEFAULT_JVM_NAMESPACE, derivedNamespace = DEFAULT_JVM_NAMESPACE))
    }

    /** In-memory stand-in for an OS-backed vault. */
    private class FakeOsVault : JvmKeyVault {
        val store = ConcurrentHashMap<String, ByteArray>()
        override val name = "FakeOsVault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? = store[alias]?.copyOf()
        override fun put(alias: String, keyBytes: ByteArray) { store[alias] = keyBytes.copyOf() }
        override fun delete(alias: String) { store.remove(alias) }
    }

    /**
     * OS vault whose lookups throw the "key vault unavailable" wording (as DPAPI / Keychain
     * do on a runtime failure). Records whether [put] ran, to prove key creation fails closed.
     */
    private class UnavailableOsVault : JvmKeyVault {
        var putCalled = false
        override val name = "UnavailableOsVault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? =
            throw IllegalStateException("KSafe: key vault unavailable — test runtime failure for \"$alias\".")
        override fun put(alias: String, keyBytes: ByteArray) { putCalled = true }
        override fun delete(alias: String) {}
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

        // The OS store already holds a stale key for this alias; the legacy DataStore key is
        // authoritative and must win (an empty vault wouldn't discriminate).
        val staleOsKey = ByteArray(32) { 0x5A }
        val fake = FakeOsVault().apply { store[alias] = staleOsKey.copyOf() }
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = fake),
        )

        // Triggers getOrCreateSecretKey → migration path.
        val ct = engine.encrypt(alias, "hello".toByteArray())
        assertEquals("hello", String(engine.decrypt(alias, ct)))

        // The stale OS key is overwritten with the real legacy bytes (so old ciphertext stays
        // decryptable) and the plaintext file is scrubbed.
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

    @Test
    fun ciphertextWrittenUnder2_0_0_stillDecryptsAfter2_1_0_keyMigration() {
        val alias = "user:token"
        val payload = "balance=4242;iban=GR16".toByteArray()

        // Software vault == legacy DataStore key location.
        val v200 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = DataStoreKeyVault(dataStore)),
        )
        val ciphertextAtRest = v200.encrypt(alias, payload)
        val key200 = DataStoreKeyVault(dataStore).get(alias)
        assertNotNull(key200, "2.0.0 must persist the AES key in the DataStore file")

        // Upgrade precondition: the per-user OS store already holds a stale key for this
        // alias, yet the at-rest ciphertext must still decrypt because the legacy DataStore
        // key is authoritative (an empty vault wouldn't discriminate).
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

        // No OS secret store → provider falls back to the legacy DataStore vault; old data
        // must still read and the key must NOT be deleted (nothing to migrate to).
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

    // Compose Desktop release case: selfTest passes at construction, but a jlinked runtime
    // missing jdk.unsupported makes JNA throw NoClassDefFoundError on the first real call, so
    // the provider must degrade to the legacy vault instead of dropping every write.

    private class LinkErrorOsVault(
        /** When true, every op throws; false lets the construction self-test pass. */
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

        // encrypt must absorb the NoClassDefFoundError by degrading — letting it
        // propagate into KSafeCore.processBatch would drop the write.
        val ct = engine.encrypt(alias, "hello".toByteArray())
        assertContentEquals("hello".toByteArray(), engine.decrypt(alias, ct))

        // Provider degraded → active vault is now the legacy DataStore.
        assertEquals(provider.legacy, provider.active)
        // The key just used must live in the legacy store, not the unreachable OS vault.
        assertNotNull(DataStoreKeyVault(dataStore).get(alias))
    }

    @Test
    fun runtimeLinkageError_preservesLegacyKey_andDecryptsExisting2_0_0Data() {
        // A user with a legacy DataStore key upgrades and ships a Compose Desktop release
        // build: the legacy key (authoritative for at-rest ciphertext) must survive and its
        // existing data must still decrypt.
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

        assertContentEquals(payload, v210.decrypt(alias, ciphertextAtRest))

        // Legacy key must survive: migration tried, JNA failed, and the read-back gate
        // prevented the delete — without it the key would be lost.
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

        // Concurrent first hits: assert all threads see consistent post-degrade state and no
        // exception escapes.
        val threads = (0 until 16).map { i ->
            Thread {
                val ct = engine.encrypt("k$i", byteArrayOf(i.toByte()))
                engine.decrypt("k$i", ct)
            }.also { it.start() }
        }
        threads.forEach { it.join() }
        assertEquals(provider.legacy, provider.active)
    }

    @Test
    fun engineDiagnostics_reflectRuntimeDegrade() {
        // The diagnostic getters must read through vaults.active, not a value frozen at
        // construction — after a degrade they must report the legacy vault, not the OS one.
        val osVault = LinkErrorOsVault().also { it.armed = true }
        val provider = JvmKeyVaultProvider(dataStore, forced = osVault)
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // Trigger the degrade with an encrypt (armed=true fails on the first real op).
        engine.encrypt("trigger", byteArrayOf(0x01))

        // name + isOsBacked now reflect the legacy fallback.
        assertEquals(false, engine.keyVaultIsOsBacked)
        assertEquals(DataStoreKeyVault(dataStore).name, engine.keyVaultName)
    }

    @Test
    fun decryptOfOrphanedCiphertext_throwsKeyNotFound_andMintsNoKey() {
        // Decrypting ciphertext whose key is gone must throw "No encryption key found" and
        // mint nothing — a get-or-create decrypt would pollute the vault with a spurious key.
        val alias = "user:token"

        val vault1 = FakeOsVault()
        val engine1 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = vault1),
        )
        val ciphertext = engine1.encrypt(alias, "secret".toByteArray())
        assertNotNull(vault1.store[alias], "precondition: encrypt created the key")

        // Orphan the ciphertext: fresh empty vault + fresh engine (empty key cache).
        val emptyVault = FakeOsVault()
        val engine2 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = emptyVault),
        )

        val ex = assertFailsWith<IllegalStateException> { engine2.decrypt(alias, ciphertext) }
        assertTrue(
            ex.message?.contains("No encryption key found", ignoreCase = true) == true,
            "decrypt of orphaned ciphertext must report 'No encryption key found', was: ${ex.message}",
        )

        assertNull(emptyVault.store[alias], "decrypt must not create a key for orphaned ciphertext")
    }

    // Construction-time transient OS-vault failure (locked Keychain, keyring not yet on
    // D-Bus): pick() must flag the vault unavailable rather than select the legacy store —
    // otherwise the orphan sweep deletes OS-vault-only ciphertext and prewarm mints a junk
    // key into the migration source that the next healthy launch copies over the real key.

    /** OS-vault stand-in that is unreachable: every op throws, so the self-test fails. */
    private class LockedOsVault : JvmKeyVault {
        override val name = "LockedOsVault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? =
            throw IllegalStateException("errSecInteractionNotAllowed (test)")
        override fun put(alias: String, keyBytes: ByteArray): Unit =
            throw IllegalStateException("errSecInteractionNotAllowed (test)")
        override fun delete(alias: String): Unit =
            throw IllegalStateException("errSecInteractionNotAllowed (test)")
    }

    @Test
    fun osVaultSelfTestFailure_flagsUnavailable_andFallsBackToLegacy() {
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = LockedOsVault())

        assertTrue(provider.osVaultUnavailable, "a failed self-test must flag the OS vault unavailable")
        assertTrue(provider.hasDegraded, "unavailable OS vault must make reads report 'unavailable' (not 'absent')")
        assertEquals(provider.legacy, provider.active, "unreachable OS vault ⇒ legacy is the active vault this session")
    }

    @Test
    fun softwareOptOut_flagsDegraded_toPreserveOsVaultCiphertext() {
        // The `-Dksafe.jvm.keyVault=software` opt-out returns the legacy vault before any
        // self-test. A missing legacy key must read as "unavailable" (sweep preserves it),
        // not "absent" (which deletes recoverable data) — yet the opt-out must still mint new
        // keys, so it must NOT set osVaultUnavailable. The OS candidate proves it short-circuits.
        System.setProperty("ksafe.jvm.keyVault", "software")
        try {
            val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = FakeOsVault())
            assertEquals(provider.legacy, provider.active, "opt-out ⇒ legacy is the active vault")
            assertTrue(
                provider.hasDegraded,
                "opt-out on a possibly-OS-vault store must report reads as 'unavailable' so the sweep preserves ciphertext",
            )
            assertFalse(
                provider.osVaultUnavailable,
                "opt-out must still mint new keys into the software store (unlike a self-test failure)",
            )
        } finally {
            System.clearProperty("ksafe.jvm.keyVault")
        }
    }

    @Test
    fun healthyOsCandidate_selectsOsVault_viaSelfTestSeam() {
        // A candidate that passes self-test is selected as the active OS vault.
        val fake = FakeOsVault()
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = fake)

        assertFalse(provider.osVaultUnavailable)
        assertFalse(provider.hasDegraded)
        assertEquals(fake, provider.active)
        assertTrue(provider.active.isOsBacked)
    }

    @Test
    fun osVaultUnavailable_refusesToMintKeyIntoLegacyMigrationSource() {
        // While the OS vault is unavailable, creating a key must NOT persist material into the
        // legacy DataStore — the next healthy launch trusts it as the migration source and
        // would copy it over the real OS-vault key.
        val alias = "user:token"
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = LockedOsVault())
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        val ex = assertFailsWith<IllegalStateException> { engine.encrypt(alias, "data".toByteArray()) }
        assertTrue(
            ex.message?.contains("unavailable", ignoreCase = true) == true,
            "key creation while the OS vault is unavailable must fail closed; was: ${ex.message}",
        )
        // Nothing was written into the legacy migration source.
        assertNull(
            DataStoreKeyVault(dataStore).get(alias),
            "no junk key may be minted into the legacy DataStore migration source",
        )
    }

    @Test
    fun osVaultUnavailable_decryptOfUnresolvableKey_reportsUnavailableNotOrphan() {
        // A value whose key lives only in the unreachable OS vault must report "unavailable",
        // not the "No encryption key found" message the orphan sweep deletes on.
        val alias = "user:token"

        // Ciphertext produced earlier under a healthy OS vault (key not in the legacy DataStore).
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault()),
        ).encrypt(alias, "secret".toByteArray())

        // Fresh launch: OS vault unreachable at construction, legacy empty.
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = LockedOsVault())
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        val ex = assertFailsWith<IllegalStateException> { engine.decrypt(alias, ciphertext) }
        val msg = ex.message.orEmpty()
        assertFalse(
            msg.contains("No encryption key found", ignoreCase = true) ||
                msg.contains("key not found", ignoreCase = true),
            "unavailable-OS-vault decrypt must NOT use the orphan-sweep delete message; was: $msg",
        )
        assertTrue(msg.contains("unavailable", ignoreCase = true), "should report vault unavailable; was: $msg")
    }

    @Test
    fun osVaultUnavailable_genuineLegacyKey_stillDecrypts_andIsNotScrubbed() {
        // Failing closed must not break the upgrade path: when the OS vault is unreachable but
        // a genuine legacy key exists in the DataStore, that key is authoritative — its data
        // must still decrypt and the key must be left in place for a later migration.
        val alias = "settings:theme"
        val payload = "dark".toByteArray()

        // Legacy style: key + ciphertext live in the legacy DataStore.
        val v200 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = DataStoreKeyVault(dataStore)),
        )
        val ciphertextAtRest = v200.encrypt(alias, payload)
        val legacyKeyBefore = DataStoreKeyVault(dataStore).get(alias)
        assertNotNull(legacyKeyBefore)

        // Upgrade launch with the OS vault unreachable.
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = LockedOsVault())
        val v210 = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        assertContentEquals(
            payload, v210.decrypt(alias, ciphertextAtRest),
            "a genuine legacy key must still decrypt even when the OS vault is unavailable",
        )
        assertContentEquals(
            legacyKeyBefore, DataStoreKeyVault(dataStore).get(alias),
            "the legacy key must be left in place (can't migrate to an unreachable OS vault)",
        )
    }

    // DPAPI / Keychain vaults map a runtime lookup failure to the "key vault unavailable"
    // contract instead of leaking a raw platform exception. These tests lock in the engine
    // half via a fake whose get() throws that wording.

    @Test
    fun runtimeUnavailableVault_decrypt_reportsUnavailableNotOrphan() {
        val alias = "user:token"
        // Ciphertext produced earlier under a healthy vault; its key is irrelevant — we assert
        // on the error wording when the vault is unreachable at read time.
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault()),
        ).encrypt(alias, "secret".toByteArray())

        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = UnavailableOsVault()),
        )
        val ex = assertFailsWith<IllegalStateException> { engine.decrypt(alias, ciphertext) }
        val msg = ex.message.orEmpty()
        assertTrue(msg.contains("unavailable", ignoreCase = true), "should report vault unavailable; was: $msg")
        assertFalse(
            msg.contains("No encryption key found", ignoreCase = true) ||
                msg.contains("key not found", ignoreCase = true),
            "must NOT use the orphan-sweep delete message (would destroy recoverable ciphertext); was: $msg",
        )
    }

    @Test
    fun runtimeUnavailableVault_encrypt_failsClosed_mintsNoKey() {
        val vault = UnavailableOsVault()
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = vault),
        )
        // Vault unreachable → can't get or safely create a key. Fail the write rather than
        // mint a divergent key a later healthy launch might treat as authoritative.
        assertFailsWith<IllegalStateException> { engine.encrypt("user:token", "data".toByteArray()) }
        assertFalse(vault.putCalled, "encrypt must fail closed — no key minted into an unavailable vault")
    }

    @Test
    fun degradedVault_decryptOfUnresolvableKey_reportsUnavailableNotOrphan() {
        // After a runtime LinkageError forces the software fallback, a key living only in the
        // unreachable OS vault must report "unavailable", not the "No encryption key found"
        // message the orphan sweep deletes on — so recoverable ciphertext survives.
        val alias = "user:token"

        // Ciphertext exists; its key value is irrelevant — we assert on the error
        // CLASS when the key is unresolvable, not on a recovered plaintext.
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault()),
        ).encrypt(alias, "secret".toByteArray())

        // Fresh engine whose OS vault fails at runtime, with an empty legacy
        // DataStore — so after the degrade the key is genuinely unresolvable.
        val osVault = LinkErrorOsVault().also { it.armed = true }
        val provider = JvmKeyVaultProvider(dataStore, forced = osVault)
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        val ex = assertFailsWith<IllegalStateException> { engine.decrypt(alias, ciphertext) }
        assertTrue(provider.hasDegraded, "precondition: the runtime failure must degrade the provider")
        val msg = ex.message.orEmpty()
        assertFalse(
            msg.contains("No encryption key found", ignoreCase = true) ||
                msg.contains("key not found", ignoreCase = true),
            "degraded decrypt must NOT use the orphan-sweep delete message; was: $msg",
        )
        assertTrue(msg.contains("unavailable", ignoreCase = true), "should report vault unavailable; was: $msg")
    }

    // Namespace-upgrade recovery: a build that derived the OS-vault namespace from
    // sun.java.command holds its keys under that derived namespace, while the current
    // constant "shared" namespace is empty. Without a read-fallback every decrypt throws
    // "No encryption key found" and the orphan sweep deletes the user's data.

    /** OS-vault stand-in whose writes fail (migration target unwritable). */
    private class ReadOnlyOsVault : JvmKeyVault {
        val store = ConcurrentHashMap<String, ByteArray>()
        override val name = "ReadOnlyOsVault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? = store[alias]?.copyOf()
        override fun put(alias: String, keyBytes: ByteArray): Unit =
            throw IllegalStateException("put refused (test)")
        override fun delete(alias: String) { store.remove(alias) }
    }

    @Test
    fun namespaceUpgrade_keyUnderDerivedNamespace_isRecoveredAndMigrated() {
        val alias = "user:token"
        val payload = "namespace-upgrade".toByteArray()

        // Derived-namespace install: the key lives under the derived-namespace location.
        val derivedNsVault = FakeOsVault()
        val ciphertextAtRest = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = derivedNsVault),
        ).encrypt(alias, payload)
        val realKey = derivedNsVault.store[alias]
        assertNotNull(realKey)

        // Current launch: lookups go to the empty "shared" namespace; the legacy-namespace
        // twin holds the real key.
        val sharedVault = FakeOsVault()
        val provider = JvmKeyVaultProvider(
            dataStore,
            forced = sharedVault,
            legacyNamespaceCandidateForTest = derivedNsVault,
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // Without the fallback this throws "No encryption key found" → the
        // orphan sweep would then permanently delete the user's ciphertext.
        assertContentEquals(payload, engine.decrypt(alias, ciphertextAtRest))

        // Migrated: written to the new namespace, scrubbed from the old one.
        assertContentEquals(realKey, sharedVault.store[alias], "key must migrate into the new namespace")
        assertNull(derivedNsVault.store[alias], "old-namespace entry must be deleted after a verified write")
    }

    @Test
    fun namespaceUpgrade_migrationWriteFails_keyStillServed_andOldEntryKept() {
        val alias = "user:token"
        val payload = "still-decrypts".toByteArray()

        val derivedNsVault = FakeOsVault()
        val ciphertextAtRest = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = derivedNsVault),
        ).encrypt(alias, payload)

        // New-namespace vault refuses writes: migration can't be finalised.
        val provider = JvmKeyVaultProvider(
            dataStore,
            forced = ReadOnlyOsVault(),
            legacyNamespaceCandidateForTest = derivedNsVault,
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // The recovered key must still serve this session…
        assertContentEquals(payload, engine.decrypt(alias, ciphertextAtRest))
        // …and the ONLY copy must not be destroyed (migration retries later).
        assertNotNull(derivedNsVault.store[alias], "old-namespace key must survive a failed migration write")
    }

    @Test
    fun namespaceUpgrade_noTwin_trueMissStillReportsNoKeyFound() {
        // Without a twin to probe, a miss is a true miss: the "No encryption key found"
        // orphan-sweep contract must be intact.
        val alias = "user:token"
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault()),
        ).encrypt(alias, "secret".toByteArray())

        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault()),
        )
        val ex = assertFailsWith<IllegalStateException> { engine.decrypt(alias, ciphertext) }
        assertTrue(ex.message.orEmpty().contains("No encryption key found"))
    }

    // Adding an explicit appNamespace makes an instance probe the "shared" default as its
    // read-fallback. But "shared" is also the live active namespace of any co-existing
    // no-namespace instance, so recovery from it must be COPY-only — the destructive delete
    // is reserved for a genuine derived legacy namespace with no live owner.

    @Test
    fun namespaceUpgrade_sharedSource_isCopiedNotMoved_soLiveSiblingKeySurvives() {
        val alias = "user:token"
        val payload = "shared-sibling".toByteArray()

        // A default (no-namespace) instance mints its LIVE key under "shared".
        val sharedVault = FakeOsVault()
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = sharedVault),
        ).encrypt(alias, payload)
        val liveKey = sharedVault.store[alias]
        assertNotNull(liveKey, "precondition: default instance minted a live key under \"shared\"")

        // A co-existing namespaced instance whose active vault is empty probes "shared" as its
        // legacy source. Recovery must COPY the key forward without deleting the sibling's live
        // entry.
        val nsVault = FakeOsVault()
        val provider = JvmKeyVaultProvider(
            dataStore,
            appNamespace = "x",
            forced = nsVault,
            legacyNamespaceCandidateForTest = sharedVault,
            legacyNamespaceNameForTest = DEFAULT_JVM_NAMESPACE,
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // The namespaced instance decrypts via the recovered key…
        assertContentEquals(payload, engine.decrypt(alias, ciphertext))
        // …the key is copied into the namespaced vault…
        assertContentEquals(liveKey, nsVault.store[alias], "key must be copied into the namespaced vault")
        // …and the sibling's LIVE "shared" key MUST survive (not MOVE-deleted).
        assertContentEquals(
            liveKey, sharedVault.store[alias],
            "H2: probing the shared default must not delete a co-existing instance's live key",
        )

        // deleteKey on the namespaced instance must also not scrub the shared sibling's key.
        engine.deleteKey(alias)
        assertNull(nsVault.store[alias], "deleteKey removes the namespaced copy")
        assertContentEquals(
            liveKey, sharedVault.store[alias],
            "H2: deleteKey on a namespaced instance must not scrub the shared sibling's key",
        )
    }

    @Test
    fun namespaceUpgrade_explicitAppNamespace_alsoProbesDerivedNamespace() {
        // A build with a stable launcher stored its key under the derived namespace, then set
        // an explicit appNamespace. "shared" is empty, so recovery must still probe the derived
        // namespace where the key lives.
        val alias = "user:token"
        val payload = "derived-and-explicit".toByteArray()

        // Derived-namespace install: key + ciphertext under the derived namespace.
        val derivedNsVault = FakeOsVault()
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = derivedNsVault),
        ).encrypt(alias, payload)
        assertNotNull(derivedNsVault.store[alias])

        // Launch with an explicit appNamespace: the active vault and "shared" are both empty;
        // only the derived namespace holds the key.
        val provider = JvmKeyVaultProvider(
            dataStore,
            appNamespace = "prod",
            forced = FakeOsVault(),
            legacyNamespaceCandidatesForTest = listOf(
                FakeOsVault() to DEFAULT_JVM_NAMESPACE, // "shared" — empty for this app
                derivedNsVault to "myapp",              // derived — where the real key lives
            ),
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // Probing only "shared" would miss and let the orphan sweep delete recoverable
        // ciphertext; probing the derived namespace recovers it.
        assertContentEquals(payload, engine.decrypt(alias, ciphertext))
        // Recovered into the active vault; the derived source is scrubbed after a verified
        // migration (a genuine derived legacy namespace with no live owner).
        assertNull(derivedNsVault.store[alias], "derived-namespace entry scrubbed after verified migration")
    }

    @Test
    fun namespaceUpgrade_legacyProbeUnavailable_reportsUnavailable_notOrphan() {
        // A transient 'vault unavailable' from the legacy-namespace probe (a keychain re-locked
        // between round-trips) must NOT be misread as a genuine miss — that would let the
        // orphan sweep delete still-recoverable ciphertext.
        val alias = "user:token"

        // Ciphertext whose key lives in the legacy namespace (produced under a healthy vault).
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault()),
        ).encrypt(alias, "secret".toByteArray())

        // Active vault empty (genuine miss under the current namespace); the legacy probe
        // throws 'vault unavailable' instead of returning the key.
        val provider = JvmKeyVaultProvider(
            dataStore,
            forced = FakeOsVault(),
            legacyNamespaceCandidateForTest = UnavailableOsVault(),
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        val ex = assertFailsWith<IllegalStateException> { engine.decrypt(alias, ciphertext) }
        val msg = ex.message.orEmpty()
        assertTrue(msg.contains("unavailable", ignoreCase = true), "should report vault unavailable; was: $msg")
        assertFalse(
            msg.contains("No encryption key found", ignoreCase = true),
            "a transient legacy-probe outage must NOT use the orphan-sweep delete message; was: $msg",
        )
    }

    @Test
    fun namespaceUpgrade_deleteKey_alsoScrubsDerivedNamespace() {
        val alias = "user:token"
        val derivedNsVault = FakeOsVault().apply { store[alias] = ByteArray(32) { 1 } }
        val sharedVault = FakeOsVault()
        val provider = JvmKeyVaultProvider(
            dataStore,
            forced = sharedVault,
            legacyNamespaceCandidateForTest = derivedNsVault,
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        engine.encrypt(alias, "v".toByteArray()) // mints into shared… or recovers old
        engine.deleteKey(alias)

        assertNull(sharedVault.store[alias], "deleteKey must remove from the active vault")
        assertNull(
            derivedNsVault.store[alias],
            "deleteKey must also scrub the derived-namespace twin, or a recreate resurrects the old key",
        )
    }

    /**
     * Shared per-user store whose first `put` triggers [onFirstPut] once — simulates another
     * instance whose self-test interleaves with ours on the same OS store.
     */
    private class RacingOsVault : JvmKeyVault {
        val store = ConcurrentHashMap<String, ByteArray>()
        @Volatile var onFirstPut: (() -> Unit)? = null
        override val name = "RacingOsVault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? = store[alias]?.copyOf()
        override fun put(alias: String, keyBytes: ByteArray) {
            store[alias] = keyBytes.copyOf()
            onFirstPut?.also { onFirstPut = null }?.invoke()
        }
        override fun delete(alias: String) { store.remove(alias) }
    }

    @Test
    fun concurrentSelfTests_onSharedOsStore_doNotFailEachOther() {
        // OS stores are per-user and shared by every instance, so self-tests must use unique
        // canary aliases: with a fixed alias, a competing self-test's delete could remove our
        // canary between put and read-back and flag a healthy vault unavailable.
        //
        // JVM tests run with `-Dksafe.jvm.keyVault=software`, which short-circuits pick()
        // before the self-test, so lift it for this test and restore.
        val prop = "ksafe.jvm.keyVault"
        val original = System.getProperty(prop)
        System.clearProperty(prop)
        try {
            val shared = RacingOsVault()
            // From inside our canary put, a competitor runs its full self-test on the same store.
            shared.onFirstPut = {
                JvmKeyVaultProvider(dataStore, osCandidateForTest = shared)
            }

            val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = shared)

            assertFalse(
                provider.osVaultUnavailable,
                "a competing self-test on the shared OS store must not fail ours (unique canary aliases)",
            )
            assertEquals(shared, provider.active, "the healthy OS vault must be selected")
        } finally {
            if (original != null) System.setProperty(prop, original)
        }
    }

    @Test
    fun legacyDerivedJvmNamespace_reproduces211Derivation() {
        val prop = "sun.java.command"
        val original = System.getProperty(prop)
        try {
            System.setProperty(prop, "com.example.MainKt --some-arg")
            assertEquals("com.example.MainKt", legacyDerivedJvmNamespace())

            System.setProperty(prop, "/opt/app/my-app-1.2.3.jar --flag")
            assertEquals("my-app-1.2.3", legacyDerivedJvmNamespace())

            System.setProperty(prop, "C:\\Program\\app.jar")
            assertEquals("app", legacyDerivedJvmNamespace())

            // Nothing distinct to probe → null.
            System.setProperty(prop, "")
            assertNull(legacyDerivedJvmNamespace())
            System.setProperty(prop, "shared")
            assertNull(legacyDerivedJvmNamespace())
        } finally {
            if (original == null) System.clearProperty(prop) else System.setProperty(prop, original)
        }
    }
}
