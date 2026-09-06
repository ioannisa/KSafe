package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeEngineMessage
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
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
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Locks in: [JvmKeyVault] wiring and legacy-key → OS-store migration, via an in-memory fake vault. */
class JvmKeyVaultMigrationTest {

    @Test
    fun legacyFallbackNamespaces_probesBothDerivedAndSharedWhenExplicitAppNamespaceSet() {
        // Either legacy location may hold the keys — derived first, then the shared default.
        assertEquals(listOf(DEFAULT_JVM_NAMESPACE), legacyFallbackNamespaces("myapp", derivedNamespace = null))
        assertEquals(
            listOf("myapp", DEFAULT_JVM_NAMESPACE),
            legacyFallbackNamespaces("com.example.app", derivedNamespace = "myapp"),
        )
    }

    @Test
    fun legacyFallbackNamespaces_probesPreCanonicalConfigNamespaceFirst() {
        // The pre-canonicalization config namespace was this app's active namespace right up
        // to the upgrade, so it holds the newest keys: probing "shared" first could migrate a
        // stale pre-namespace key over the live one.
        assertEquals(
            listOf(".foo", "myapp", DEFAULT_JVM_NAMESPACE),
            legacyFallbackNamespaces("foo", derivedNamespace = "myapp", legacyConfigNamespace = ".foo"),
        )
        // One equal to the current namespace is filtered like any other.
        assertEquals(
            listOf(DEFAULT_JVM_NAMESPACE),
            legacyFallbackNamespaces("foo", derivedNamespace = null, legacyConfigNamespace = "foo"),
        )
    }

    @Test
    fun legacyFallbackNamespaces_probesDerivedWhenOnDefaultNamespace() {
        assertEquals(listOf("derived-ns"), legacyFallbackNamespaces(DEFAULT_JVM_NAMESPACE, derivedNamespace = "derived-ns"))
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

        // The OS store holds a stale key; the legacy one is authoritative and must win (an
        // empty vault wouldn't discriminate).
        val staleOsKey = ByteArray(32) { 0x5A }
        val fake = FakeOsVault().apply { store[alias] = staleOsKey.copyOf() }
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = fake),
        )

        // Triggers getOrCreateSecretKey → migration path.
        val ct = engine.encrypt(alias, "hello".toByteArray())
        assertEquals("hello", String(engine.decrypt(alias, ct)))

        // The real legacy bytes must win, so old ciphertext stays decryptable.
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

        // Upgrade precondition: a stale OS key for the alias (an empty vault wouldn't discriminate).
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

        // No OS secret store → legacy vault; old data must still read and the key must stay
        // in place (nothing to migrate it to).
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

        // Sweep without any prior encrypt/decrypt — proves it's eager, not lazy.
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

        assertEquals(provider.legacy, provider.active)
        // The key just used must live in the legacy store, not the unreachable OS vault.
        assertNotNull(DataStoreKeyVault(dataStore).get(alias))
    }

    @Test
    fun runtimeLinkageError_preservesLegacyKey_andDecryptsExisting2_0_0Data() {
        // A user with a legacy DataStore key ships a Compose Desktop release build: that key is
        // authoritative for at-rest ciphertext, so it must survive and its data must still read.
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

        // Concurrent first hits: no exception may escape and the degrade must settle once.
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
        // The diagnostics must read through vaults.active, not a value frozen at construction.
        val osVault = LinkErrorOsVault().also { it.armed = true }
        val provider = JvmKeyVaultProvider(dataStore, forced = osVault)
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // Trigger the degrade with an encrypt (armed=true fails on the first real op).
        engine.encrypt("trigger", byteArrayOf(0x01))

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
        // self-test. A missing legacy key must read as "unavailable" (sweep preserves it), not
        // "absent" (which deletes recoverable data) — yet it must still mint new keys.
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

    // A vault whose native bridge never links is dead in-process, not locked-but-present. On
    // Windows JNA resolves lazily inside the first put/get, i.e. inside the self-test, so the
    // link failure must degrade to the software vault instead of failing every write closed.

    /** OS-vault stand-in whose every op dies with a `LinkageError` (JNA cannot load). */
    private class UnlinkableOsVault : JvmKeyVault {
        override val name = "UnlinkableOsVault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? = throw UnsatisfiedLinkError("jnidispatch")
        override fun put(alias: String, keyBytes: ByteArray): Unit = throw UnsatisfiedLinkError("jnidispatch")
        override fun delete(alias: String): Unit = throw UnsatisfiedLinkError("jnidispatch")
    }

    @Test
    fun osVaultLinkageFailureInSelfTest_degradesToLegacy_ratherThanFailingClosed() = withoutSoftwareOptOut {
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = UnlinkableOsVault())

        assertSame(provider.legacy, provider.active, "an unlinkable OS vault ⇒ legacy is the active vault")
        assertTrue(provider.hasDegraded, "reads must still report 'unavailable' so no ciphertext is swept")
        assertFalse(
            provider.osVaultUnavailable,
            "a native-link failure is an in-process death, not a locked vault — minting must stay allowed",
        )
    }

    @Test
    fun osVaultLinkageFailureInSelfTest_encryptSucceeds_andUnknownKeyReportsUnavailable() = withoutSoftwareOptOut {
        val alias = "user:token"

        // Ciphertext whose key never reaches this store, so the read below is a genuine miss.
        val orphanCiphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault()),
        ).encrypt("unknown", "secret".toByteArray())

        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = UnlinkableOsVault())
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        val ct = engine.encrypt(alias, "data".toByteArray())
        assertContentEquals("data".toByteArray(), engine.decrypt(alias, ct))
        assertNotNull(
            DataStoreKeyVault(dataStore).get(alias),
            "an unlinkable OS vault must still mint into the software vault",
        )
        assertNotNull(
            DataStoreKeyVault(dataStore).get("$alias.${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}"),
            "a degraded mint must carry the custody marker the next healthy launch relies on",
        )

        val ex = assertFailsWith<IllegalStateException> { engine.decrypt("unknown", orphanCiphertext) }
        val msg = ex.message.orEmpty()
        assertTrue(
            msg.contains(KSafeEngineMessage.VAULT_UNAVAILABLE, ignoreCase = true),
            "should report vault unavailable; was: $msg",
        )
        assertFalse(
            msg.contains("No encryption key found", ignoreCase = true),
            "must NOT use the orphan-sweep delete message; was: $msg",
        )
    }

    @Test
    fun healthyOsCandidate_selectsOsVault_viaSelfTestSeam() {
        val fake = FakeOsVault()
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = fake)

        assertFalse(provider.osVaultUnavailable)
        assertFalse(provider.hasDegraded)
        assertEquals(fake, provider.active)
        assertTrue(provider.active.isOsBacked)
    }

    @Test
    fun osVaultUnavailable_refusesToMintKeyIntoLegacyMigrationSource() {
        // Creating a key while the OS vault is unavailable must not persist material into the
        // legacy DataStore: the next healthy launch would copy it over the real OS-vault key.
        val alias = "user:token"
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = LockedOsVault())
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        val ex = assertFailsWith<IllegalStateException> { engine.encrypt(alias, "data".toByteArray()) }
        assertTrue(
            ex.message?.contains("unavailable", ignoreCase = true) == true,
            "key creation while the OS vault is unavailable must fail closed; was: ${ex.message}",
        )
        assertNull(
            DataStoreKeyVault(dataStore).get(alias),
            "no junk key may be minted into the legacy DataStore migration source",
        )
    }

    @Test
    fun osVaultUnavailable_decryptOfUnresolvableKey_reportsUnavailableNotOrphan() {
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
        // Failing closed must not break the upgrade path: a genuine legacy key is authoritative.
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

    // DPAPI / Keychain map a runtime lookup failure to the "key vault unavailable" contract
    // instead of leaking a raw platform exception; these lock in the engine half of that.

    @Test
    fun runtimeUnavailableVault_decrypt_reportsUnavailableNotOrphan() {
        val alias = "user:token"
        // Produced under a healthy vault; the key value is irrelevant, the error wording is not.
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
        val alias = "user:token"

        // The key value is irrelevant — the assertion is on the error, not a recovered plaintext.
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault()),
        ).encrypt(alias, "secret".toByteArray())

        // Fresh engine, OS vault failing at runtime, legacy empty — the key is unresolvable.
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
    // sun.java.command holds its keys there while the current "shared" namespace is empty.
    // Without a read-fallback every decrypt throws and the orphan sweep deletes the user's data.

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

        // Derived-namespace install: the key lives under the derived namespace.
        val derivedNsVault = FakeOsVault()
        val ciphertextAtRest = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = derivedNsVault),
        ).encrypt(alias, payload)
        val realKey = derivedNsVault.store[alias]
        assertNotNull(realKey)

        // Current launch: lookups go to the empty "shared" namespace; the twin holds the key.
        val sharedVault = FakeOsVault()
        val provider = JvmKeyVaultProvider(
            dataStore,
            forced = sharedVault,
            legacyNamespaceCandidateForTest = derivedNsVault,
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // Without the fallback this throws and the orphan sweep deletes the user's ciphertext.
        assertContentEquals(payload, engine.decrypt(alias, ciphertextAtRest))

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

        assertContentEquals(payload, engine.decrypt(alias, ciphertextAtRest))
        // The only copy must not be destroyed (migration retries later).
        assertNotNull(derivedNsVault.store[alias], "old-namespace key must survive a failed migration write")
    }

    @Test
    fun namespaceUpgrade_noTwin_trueMissStillReportsNoKeyFound() {
        // With no twin to probe, a miss is a true miss — the orphan-sweep contract stays intact.
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

    // An explicit appNamespace makes an instance probe the "shared" default as its read-
    // fallback. But "shared" is also the live namespace of any co-existing no-namespace
    // instance, so recovery from it must copy; the delete is for a derived legacy namespace.

    @Test
    fun namespaceUpgrade_sharedSource_isCopiedNotMoved_soLiveSiblingKeySurvives() {
        val alias = "user:token"
        val payload = "shared-sibling".toByteArray()

        // A default (no-namespace) instance mints its live key under "shared".
        val sharedVault = FakeOsVault()
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = sharedVault),
        ).encrypt(alias, payload)
        val liveKey = sharedVault.store[alias]
        assertNotNull(liveKey, "precondition: default instance minted a live key under \"shared\"")

        // A co-existing namespaced instance with an empty active vault probes "shared" as its
        // legacy source.
        val nsVault = FakeOsVault()
        val provider = JvmKeyVaultProvider(
            dataStore,
            appNamespace = "x",
            forced = nsVault,
            legacyNamespaceCandidateForTest = sharedVault,
            legacyNamespaceNameForTest = DEFAULT_JVM_NAMESPACE,
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        assertContentEquals(payload, engine.decrypt(alias, ciphertext))
        assertContentEquals(liveKey, nsVault.store[alias], "key must be copied into the namespaced vault")
        // The sibling's live "shared" key must survive — a copy, never a move.
        assertContentEquals(
            liveKey, sharedVault.store[alias],
            "H2: probing the shared default must not delete a co-existing instance's live key",
        )

        engine.deleteKey(alias)
        assertNull(nsVault.store[alias], "deleteKey removes the namespaced copy")
        assertContentEquals(
            liveKey, sharedVault.store[alias],
            "H2: deleteKey on a namespaced instance must not scrub the shared sibling's key",
        )
    }

    @Test
    fun namespaceCanonicalization_oldVaultNamespace_isCopiedNotMoved_soAnOlderInstanceKeepsItsKey() {
        // A pre-canonicalization vault namespace (".foo", now resolved as "foo") may still be
        // owned by a not-yet-upgraded instance, so recovery must copy, like the "shared" default.
        val alias = "user:token"
        val payload = "pre-canonical".toByteArray()

        // A pre-upgrade instance minted the live key under the old-normalization namespace.
        val oldNsVault = FakeOsVault()
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = oldNsVault),
        ).encrypt(alias, payload)
        val liveKey = oldNsVault.store[alias]
        assertNotNull(liveKey)

        // Upgraded launch: the canonical namespace is empty; the pre-canonical twin is probed.
        val nsVault = FakeOsVault()
        val provider = JvmKeyVaultProvider(
            dataStore,
            appNamespace = "foo",
            legacyAppNamespace = ".foo",
            forced = nsVault,
            legacyNamespaceCandidateForTest = oldNsVault,
            legacyNamespaceNameForTest = ".foo",
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        assertContentEquals(payload, engine.decrypt(alias, ciphertext))
        assertContentEquals(liveKey, nsVault.store[alias], "key must be copied into the canonical namespace")
        assertContentEquals(
            liveKey, oldNsVault.store[alias],
            "the pre-canonicalization namespace may still have a live owner — recovery must not reclaim it",
        )

        engine.deleteKey(alias)
        assertNull(nsVault.store[alias], "deleteKey removes the canonical-namespace copy")
        assertContentEquals(
            liveKey, oldNsVault.store[alias],
            "deleteKey on the upgraded instance must not scrub the pre-canonicalization twin",
        )
    }

    @Test
    fun namespaceUpgrade_explicitAppNamespace_alsoProbesDerivedNamespace() {
        // A build with a stable launcher stored its key under the derived namespace, then set an
        // explicit appNamespace: "shared" is empty, so the derived namespace must still be probed.
        val alias = "user:token"
        val payload = "derived-and-explicit".toByteArray()

        // Derived-namespace install: key + ciphertext under the derived namespace.
        val derivedNsVault = FakeOsVault()
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = derivedNsVault),
        ).encrypt(alias, payload)
        assertNotNull(derivedNsVault.store[alias])

        // Explicit appNamespace: active vault and "shared" empty; only the derived one has the key.
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

        // Probing only "shared" would miss and let the orphan sweep delete recoverable data.
        assertContentEquals(payload, engine.decrypt(alias, ciphertext))
        // A genuine derived legacy namespace has no live owner, so it is scrubbed after the copy.
        assertNull(derivedNsVault.store[alias], "derived-namespace entry scrubbed after verified migration")
    }

    @Test
    fun namespaceUpgrade_legacyProbeUnavailable_reportsUnavailable_notOrphan() {
        // A transient 'vault unavailable' from the legacy-namespace probe (a keychain re-locked
        // between round-trips) must not read as a genuine miss — the sweep would delete the data.
        val alias = "user:token"

        // Ciphertext whose key lives in the legacy namespace (produced under a healthy vault).
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault()),
        ).encrypt(alias, "secret".toByteArray())

        // Active vault empty; the legacy probe throws 'vault unavailable' instead of the key.
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
        // OS stores are per-user and shared by every instance, so self-tests need unique canary
        // aliases: a competing self-test's delete could otherwise remove ours between put and
        // read-back and flag a healthy vault unavailable. jvmTest sets
        // `-Dksafe.jvm.keyVault=software`, which short-circuits pick(), so lift it here.
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

    // Prewarm runs outside the store's commit mutex and its output is discarded, so it must
    // never re-persist the key it warmed: a clearAll() landing mid-prewarm would be silently
    // undone — the erased key returns and old ciphertext backups decrypt again.

    /** Vault whose first `put` triggers [onFirstPut] once — simulates a concurrent clearAll. */
    private class PutHookOsVault : JvmKeyVault {
        val store = ConcurrentHashMap<String, ByteArray>()
        @Volatile var onFirstPut: (() -> Unit)? = null
        override val name = "PutHookOsVault (test)"
        override val isOsBacked = true
        override fun get(alias: String): ByteArray? = store[alias]?.copyOf()
        override fun put(alias: String, keyBytes: ByteArray) {
            store[alias] = keyBytes.copyOf()
            onFirstPut?.also { onFirstPut = null }?.invoke()
        }
        override fun delete(alias: String) { store.remove(alias) }
    }

    @Test
    fun prewarm_doesNotRepersistKey_afterConcurrentClearAll() {
        val alias = "master.g1"
        val vault = PutHookOsVault()
        val provider = JvmKeyVaultProvider(dataStore, forced = vault)
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // The instant prewarm mints its key, a clearAll wipes the vault and bumps the purge
        // epoch — the exact interleaving whose encrypt-path repair used to re-put the key.
        vault.onFirstPut = {
            vault.store.clear()
            engine.onStoreCleared()
        }
        runBlocking { engine.prewarmKey(alias) }

        assertTrue(
            vault.store.isEmpty(),
            "prewarm must not re-persist a key a concurrent clearAll erased (cryptographic erasure)",
        )

        // The next real encrypt mints a fresh key — the stale cached one is never served.
        val ct = engine.encrypt(alias, "post-clear".toByteArray())
        assertNotNull(vault.store[alias], "a real write after the clear mints a fresh durable key")
        assertContentEquals("post-clear".toByteArray(), engine.decrypt(alias, ct))
    }

    @Test
    fun prewarm_stillWarmsAndPersistsKey_whenNoClearRaces() {
        val alias = "master.g1"
        val vault = FakeOsVault()
        val provider = JvmKeyVaultProvider(dataStore, forced = vault)
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        runBlocking { engine.prewarmKey(alias) }
        val warmed = vault.store[alias]
        assertNotNull(warmed, "prewarm must mint + persist the key when nothing races it")

        // The warmed key is the one real work uses (cache hit, no re-mint).
        val ct = engine.encrypt(alias, "warm".toByteArray())
        assertContentEquals(warmed, vault.store[alias], "encrypt must reuse the prewarmed key")
        assertContentEquals("warm".toByteArray(), engine.decrypt(alias, ct))
    }

    // A retained legacy-namespace source ("shared", or the pre-canonicalization namespace) can
    // never be reclaim-deleted — a sibling may own it live. Without a persistent tombstone a
    // fresh engine's read-fallback would re-copy a deliberately deleted key.

    @Test
    fun deletedKey_isNotResurrected_fromTheRetainedSharedSource_byAFreshEngine() {
        val alias = "user:token"
        val payload = "shared-sibling".toByteArray()

        // The shared default holds the live key (minted by a co-existing default instance).
        val sharedVault = FakeOsVault()
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = sharedVault),
        ).encrypt(alias, payload)
        val sharedKey = sharedVault.store[alias]
        assertNotNull(sharedKey)

        // Namespaced instance recovers the key (copy), then deletes it.
        val nsVault = FakeOsVault()
        fun provider() = JvmKeyVaultProvider(
            dataStore,
            appNamespace = "x",
            forced = nsVault,
            legacyNamespaceCandidateForTest = sharedVault,
            legacyNamespaceNameForTest = DEFAULT_JVM_NAMESPACE,
        )
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider())
        assertContentEquals(payload, engine.decrypt(alias, ciphertext), "precondition: recovery works")
        engine.deleteKey(alias)
        assertNull(nsVault.store[alias], "deleteKey removes the namespaced copy")

        // A fresh engine (new caches, same vaults) must not re-adopt the shared key.
        val fresh = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider())
        assertFailsWith<IllegalStateException>("deleted key must not be re-copied from the shared source") {
            fresh.decrypt(alias, ciphertext)
        }
        // A recreate mints a fresh key instead of resurrecting the deleted one.
        fresh.encrypt(alias, "new-era".toByteArray())
        val recreated = nsVault.store[alias]
        assertNotNull(recreated, "recreate must mint a key in the namespaced vault")
        assertFalse(
            recreated.contentEquals(sharedKey),
            "recreate must NOT reuse the deleted (pre-clear) key material",
        )
        assertContentEquals(sharedKey, sharedVault.store[alias], "the retained shared source must survive")
    }

    @Test
    fun deleteOfANeverRecoveredAlias_doesNotBlockALaterGenuineUpgradeRecovery() {
        // Deleting an alias the shared source does not hold must not tombstone it: the tombstone
        // is only for keys deliberately deleted while the source held them.
        val alias = "user:token"
        val sharedVault = FakeOsVault()
        val nsVault = FakeOsVault()
        fun provider() = JvmKeyVaultProvider(
            dataStore,
            appNamespace = "x",
            forced = nsVault,
            legacyNamespaceCandidateForTest = sharedVault,
            legacyNamespaceNameForTest = DEFAULT_JVM_NAMESPACE,
        )

        // Delete while the shared source has nothing for this alias.
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider())
        engine.encrypt(alias, "own".toByteArray())
        engine.deleteKey(alias)

        // The shared source later holds a key (e.g. the sibling minted it) with ciphertext.
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = sharedVault),
        ).encrypt(alias, "sibling".toByteArray())

        val fresh = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider())
        assertContentEquals(
            "sibling".toByteArray(), fresh.decrypt(alias, ciphertext),
            "an alias never deleted-while-present must keep its upgrade recovery path",
        )
    }

    // Custody-marker conflict guard: a key minted into the legacy slot by a fallback session
    // carries a marker, and must not overwrite a different live OS-vault key (both are kept,
    // the session reads with the legacy one). A marker-less pre-2.x key stays authoritative.

    @Test
    fun fallbackMintedLegacyKey_doesNotOverwriteDifferentLiveOsKey_andSessionUsesLegacy() {
        val alias = "user:token"
        val payload = "minted-under-fallback".toByteArray()

        // Opt-out session: keys mint into the legacy DataStore slot with the custody marker.
        // (Save/restore — the jvmTest JVM sets this property globally.)
        val prop = "ksafe.jvm.keyVault"
        val original = System.getProperty(prop)
        System.setProperty(prop, "software")
        val ciphertext: ByteArray
        try {
            val optOutEngine = JvmSoftwareEncryption(
                dataStore = dataStore,
                vaultProvider = JvmKeyVaultProvider(dataStore),
            )
            ciphertext = optOutEngine.encrypt(alias, payload)
        } finally {
            if (original != null) System.setProperty(prop, original) else System.clearProperty(prop)
        }
        val legacy = DataStoreKeyVault(dataStore)
        val legacyKey = legacy.get(alias)
        assertNotNull(legacyKey, "precondition: the opt-out session minted into the legacy slot")
        assertNotNull(
            legacy.get("$alias.__ksafe_swfb__"),
            "precondition: the fallback mint must carry its custody marker",
        )

        // Healthy launch: the OS vault holds a different live key for the same alias.
        val liveOsKey = ByteArray(32) { 0x5A }
        val osVault = FakeOsVault().apply { store[alias] = liveOsKey.copyOf() }
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        )

        // The session keeps reading with the legacy key — visible behavior unchanged.
        assertContentEquals(payload, engine.decrypt(alias, ciphertext))
        assertContentEquals(
            liveOsKey, osVault.store[alias],
            "a fallback-minted legacy key must never overwrite a different live OS-vault key",
        )
        // Both copies survive — the legacy key and marker stay for later resolution.
        assertContentEquals(legacyKey, legacy.get(alias), "the legacy key must be kept, not scrubbed")
        assertNotNull(legacy.get("$alias.__ksafe_swfb__"), "the custody marker must be kept with it")
    }

    @Test
    fun markerlessGenuineLegacyKey_staysAuthoritative_andReplacesStaleOsCopy() {
        // A genuine pre-2.x legacy key (old binaries wrote no custody marker) provably encrypted
        // this store's ciphertext, so it must still replace a stale OS copy.
        val alias = "settings:theme"
        val payload = "dark".toByteArray()

        val legacy = DataStoreKeyVault(dataStore)
        val v200 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = legacy),
        )
        val ciphertext = v200.encrypt(alias, payload)
        val genuineKey = legacy.get(alias)
        assertNotNull(genuineKey)
        assertNull(legacy.get("$alias.__ksafe_swfb__"), "precondition: a genuine legacy key has NO marker")

        val staleOsVault = FakeOsVault().apply { store[alias] = ByteArray(32) { 0x11 } }
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = staleOsVault),
        )

        assertContentEquals(payload, engine.decrypt(alias, ciphertext))
        assertContentEquals(
            genuineKey, staleOsVault.store[alias],
            "a marker-less genuine legacy key must replace the stale OS copy",
        )
        assertNull(legacy.get(alias), "the migrated legacy copy is scrubbed after verification")
    }

    // An involuntary degrade (dead JNA bridge) also mints into the legacy slot, but that key is
    // provisional: a live OS key for the same alias predates it and must stay authoritative.

    @Test
    fun degradedMint_doesNotShadowTheLiveOsKey_onTheNextHealthyLaunch() = withoutSoftwareOptOut {
        val alias = "user:token"
        val healthyPayload = "written-before-the-bridge-died".toByteArray()

        // Healthy launch: the key lands in the OS vault and a value is written under it.
        val osVault = FakeOsVault()
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        ).encrypt(alias, healthyPayload)
        val osKey = osVault.store[alias]
        assertNotNull(osKey, "precondition: the healthy launch minted into the OS vault")

        // Degraded launch: JNA cannot link, so this session mints into the software vault.
        JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, osCandidateForTest = UnlinkableOsVault()),
        ).encrypt(alias, "written-while-degraded".toByteArray())
        assertNotNull(
            DataStoreKeyVault(dataStore).get(alias),
            "precondition: the degraded session minted a local key",
        )

        // Next healthy launch: the OS key wins again, so the pre-degrade value still reads.
        val healed = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        )
        assertContentEquals(healthyPayload, healed.decrypt(alias, ciphertext))
        assertContentEquals(osKey, osVault.store[alias], "the live OS key must not be replaced")
    }

    @Test
    fun degradedFirstInstall_keepsItsKey_andMigratesItOnTheFirstHealthyLaunch() = withoutSoftwareOptOut {
        val alias = "user:token"
        val payload = "written-while-degraded".toByteArray()

        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, osCandidateForTest = UnlinkableOsVault()),
        ).encrypt(alias, payload)
        val mintedKey = DataStoreKeyVault(dataStore).get(alias)
        assertNotNull(mintedKey, "precondition: the degraded session minted a local key")

        // The OS vault holds nothing for this alias, so nothing outranks the provisional key.
        val osVault = FakeOsVault()
        val healthy = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        )
        assertContentEquals(payload, healthy.decrypt(alias, ciphertext))
        assertContentEquals(
            mintedKey, osVault.store[alias],
            "the degraded-session key must migrate in, not be dropped",
        )
        assertNull(DataStoreKeyVault(dataStore).get(alias), "the migrated legacy copy is scrubbed")
        assertNull(
            DataStoreKeyVault(dataStore).get("$alias.${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}"),
            "the custody marker goes with the key it described",
        )
    }

    @Test
    fun degradedSessionWrites_stillDecrypt_afterTheOsVaultReturns() = withoutSoftwareOptOut {
        val alias = "user:token"
        val osVault = FakeOsVault()
        val beforeCiphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        ).encrypt(alias, "before".toByteArray())

        // The bridge dies: this session mints a provisional key and writes under it, which also
        // rewrites the record of the pre-failure value.
        val degradedCiphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, osCandidateForTest = UnlinkableOsVault()),
        ).encrypt(alias, "during".toByteArray())

        // Healed: the OS key owns the alias again, and the kept provisional key covers the rest.
        val healed = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        )
        assertContentEquals("before".toByteArray(), healed.decrypt(alias, beforeCiphertext))
        assertContentEquals("during".toByteArray(), healed.decrypt(alias, degradedCiphertext))
    }

    @Test
    fun degradedFirstInstall_ontoAStaleOsKey_stillDecrypts() = withoutSoftwareOptOut {
        val alias = "user:token"
        val payload = "written-while-degraded".toByteArray()
        val staleOsKey = ByteArray(32) { 0x5A }
        val osVault = FakeOsVault().apply { store[alias] = staleOsKey.copyOf() }

        // Fresh data dir, permanently dead bridge (a jlink runtime without `jdk.unsupported`),
        // and a leftover OS entry for the same alias from a previous install.
        val ciphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, osCandidateForTest = UnlinkableOsVault()),
        ).encrypt(alias, payload)

        val healed = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        )
        assertContentEquals(payload, healed.decrypt(alias, ciphertext))
        assertContentEquals(staleOsKey, osVault.store[alias], "the OS key stays authoritative for the alias")
    }

    @Test
    fun deliberateOptOut_takesCustodyOfAProvisionalKey() = withoutSoftwareOptOut {
        val alias = "user:token"
        val markerAlias = "$alias.${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}"

        // Dead bridge: the key this session mints is provisional.
        JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, osCandidateForTest = UnlinkableOsVault()),
        ).encrypt(alias, "degraded".toByteArray())
        assertContentEquals(byteArrayOf(2), DataStoreKeyVault(dataStore).get(markerAlias))

        withSoftwareOptOut {
            JvmSoftwareEncryption(
                dataStore = dataStore,
                vaultProvider = JvmKeyVaultProvider(dataStore, osCandidateForTest = FakeOsVault()),
            ).encrypt(alias, "deliberate".toByteArray())
        }

        assertContentEquals(
            byteArrayOf(1), DataStoreKeyVault(dataStore).get(markerAlias),
            "a deliberate opt-out owns the key it resolved, so custody is no longer involuntary",
        )

        // The opt-out contract: the next healthy launch continues with the local key, so a value
        // it writes is readable by a software-only engine.
        val osVault = FakeOsVault().apply { store[alias] = ByteArray(32) { 0x5A } }
        val healthyCiphertext = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = osVault),
        ).encrypt(alias, "after".toByteArray())
        val softwareOnly = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = DataStoreKeyVault(dataStore)),
        )
        assertContentEquals("after".toByteArray(), softwareOnly.decrypt(alias, healthyCiphertext))
    }

    @Test
    fun prewarm_mintsNothing_whileTheNativeBridgeIsDead() = withoutSoftwareOptOut {
        val alias = "master.g1"
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, osCandidateForTest = UnlinkableOsVault()),
        )

        runBlocking { engine.prewarmKey(alias) }

        assertNull(
            DataStoreKeyVault(dataStore).get(alias),
            "a read-only session under a dead bridge must leave the store untouched",
        )
        assertNull(DataStoreKeyVault(dataStore).get("$alias.${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}"))
    }

    /** Legacy vault that runs a one-shot hook on its next get, to land a degrade mid-migration. */
    private class HookedLegacyVault(private val inner: JvmKeyVault) : JvmKeyVault {
        var onNextGet: (() -> Unit)? = null
        override val name = "HookedLegacyVault (test)"
        override val isOsBacked = false
        override fun get(alias: String): ByteArray? {
            onNextGet?.let { onNextGet = null; it() }
            return inner.get(alias)
        }
        override fun put(alias: String, keyBytes: ByteArray) = inner.put(alias, keyBytes)
        override fun delete(alias: String) = inner.delete(alias)
    }

    @Test
    fun degradeDuringMigration_keepsTheLegacyKeyAndItsMarker() = withoutSoftwareOptOut {
        val alias = "user:token"
        val markerAlias = "$alias.${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}"
        val store = DataStoreKeyVault(dataStore)
        val legacyKey = ByteArray(32) { it.toByte() }
        store.put(alias, legacyKey)
        store.put(markerAlias, byteArrayOf(2))

        val legacy = HookedLegacyVault(store)
        val provider = JvmKeyVaultProvider(dataStore, forced = FakeOsVault(), legacyOverride = legacy)
        // Stands in for another alias' thread degrading the provider after resolveKeyVia's snapshot.
        legacy.onNextGet = { provider.degradeToLegacy(UnsatisfiedLinkError("jnidispatch")) }

        JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)
            .encrypt(alias, "data".toByteArray())

        assertContentEquals(
            legacyKey, store.get(alias),
            "a degrade mid-migration must not delete the only copy of the key",
        )
        assertNotNull(store.get(markerAlias), "the custody marker must survive with the key it describes")
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

    /** Legacy vault that records put order and can fail custody-marker puts. */
    private class RecordingLegacyVault(
        private val inner: JvmKeyVault,
        private val failMarkerPut: Boolean,
    ) : JvmKeyVault {
        val puts = mutableListOf<String>()
        override val name = "RecordingLegacyVault (test)"
        override val isOsBacked = false
        override fun get(alias: String): ByteArray? = inner.get(alias)
        override fun put(alias: String, keyBytes: ByteArray) {
            puts += alias
            if (failMarkerPut && alias.endsWith(KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK)) {
                throw IOException("simulated marker write failure")
            }
            inner.put(alias, keyBytes)
        }
        override fun delete(alias: String) = inner.delete(alias)
    }

    /** Lifts the suite-wide `-Dksafe.jvm.keyVault=software`, so pick() reaches the self-test. */
    private inline fun withoutSoftwareOptOut(block: () -> Unit) {
        // The env twin cannot be unset from inside a JVM, so assert it away: set, it would re-arm
        // the opt-out and silently invert every custody-marker assertion below.
        assertNull(System.getenv("KSAFE_JVM_KEY_VAULT"), "KSAFE_JVM_KEY_VAULT must not be set for these tests")
        val prev = System.getProperty("ksafe.jvm.keyVault")
        System.clearProperty("ksafe.jvm.keyVault")
        try {
            block()
        } finally {
            if (prev != null) System.setProperty("ksafe.jvm.keyVault", prev)
        }
    }

    private inline fun withSoftwareOptOut(block: () -> Unit) {
        val prev = System.getProperty("ksafe.jvm.keyVault")
        System.setProperty("ksafe.jvm.keyVault", "software")
        try {
            block()
        } finally {
            if (prev == null) System.clearProperty("ksafe.jvm.keyVault") else System.setProperty("ksafe.jvm.keyVault", prev)
        }
    }

    @Test
    fun fallbackMint_writesCustodyMarkerBeforeKey() = withSoftwareOptOut {
        val alias = "user:token"
        val legacy = RecordingLegacyVault(DataStoreKeyVault(dataStore), failMarkerPut = false)
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, legacyOverride = legacy),
        )

        engine.encrypt(alias, "data".toByteArray())

        assertEquals(
            listOf("$alias.${KSafeReservedKeys.VAULT_SOFTWARE_FALLBACK}", alias),
            legacy.puts,
            "the custody marker must be durable before the key it describes",
        )
    }

    @Test
    fun fallbackMint_markerWriteFailure_mintsNoKey() = withSoftwareOptOut {
        val alias = "user:token"
        val store = DataStoreKeyVault(dataStore)
        val legacy = RecordingLegacyVault(store, failMarkerPut = true)
        val engine = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, legacyOverride = legacy),
        )

        assertFailsWith<IOException> { engine.encrypt(alias, "data".toByteArray()) }
        assertNull(store.get(alias), "an unmarked fallback key must never reach the legacy vault")
    }
}
