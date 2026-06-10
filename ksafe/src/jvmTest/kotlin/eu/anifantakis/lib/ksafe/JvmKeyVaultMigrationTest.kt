package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStoreKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.keyvault.legacyDerivedJvmNamespace
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

    /**
     * OS vault whose lookups fail at RUNTIME with the "key vault unavailable" wording —
     * what the Windows DPAPI / macOS Keychain vaults now throw on a non-LinkageError runtime
     * failure (DPAPI blob undecryptable / login keychain locked) per deep-review #57. Records
     * whether [put] was ever called, to prove key creation fails closed (no junk key minted).
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

    @Test
    fun engineDiagnostics_reflectRuntimeDegrade() {
        // Pre-2.1.1, JvmSoftwareEncryption.keyVaultIsOsBacked / keyVaultName
        // were read once at KSafe construction and frozen in
        // KSafe.protectionInfo. After a runtime degrade the snapshot lied:
        // it still reported the OS vault even though writes were going to
        // the legacy file. This test pins the new contract — the engine's
        // diagnostic getters read through vaults.active, so the captured
        // protectionInfoProvider in KSafe sees the post-degrade truth.
        val osVault = LinkErrorOsVault().also { it.armed = true }
        val provider = JvmKeyVaultProvider(dataStore, forced = osVault)
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        // Pre-degrade snapshot: still reports the OS vault (selfTest passed,
        // armed=true only kicks in on the next real op).
        // Trigger the degrade by doing an encrypt.
        engine.encrypt("trigger", byteArrayOf(0x01))

        // Post-degrade: name + isOsBacked must reflect the legacy fallback.
        assertEquals(false, engine.keyVaultIsOsBacked)
        assertEquals(DataStoreKeyVault(dataStore).name, engine.keyVaultName)
    }

    @Test
    fun decryptOfOrphanedCiphertext_throwsKeyNotFound_andMintsNoKey() {
        // Regression for the JVM decrypt-creates-a-key bug: JVM `decrypt` used to
        // call getOrCreateSecretKey, so decrypting ciphertext whose key was gone
        // (OS-vault wiped / reinstall) MINTED a fresh junk key into the vault and
        // failed with a GCM "tag mismatch" instead of "No encryption key found".
        // Consequences: (1) the orphan sweep — which matches "No encryption key
        // found" / "key not found" — never reclaimed JVM orphans, and (2) a
        // spurious key polluted the user's OS vault on every failed decrypt.
        // JVM decrypt must now behave like Android/Apple: throw, mint nothing.
        val alias = "user:token"

        // 1. Encrypt with a real key in the vault.
        val vault1 = FakeOsVault()
        val engine1 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = vault1),
        )
        val ciphertext = engine1.encrypt(alias, "secret".toByteArray())
        assertNotNull(vault1.store[alias], "precondition: encrypt created the key")

        // 2. Orphan the ciphertext: fresh, EMPTY vault + fresh engine (empty key
        //    cache) — the key is gone and not cached anywhere.
        val emptyVault = FakeOsVault()
        val engine2 = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = emptyVault),
        )

        // 3. Decrypt must throw the cleanup-recognised message…
        val ex = assertFailsWith<IllegalStateException> { engine2.decrypt(alias, ciphertext) }
        assertTrue(
            ex.message?.contains("No encryption key found", ignoreCase = true) == true,
            "decrypt of orphaned ciphertext must report 'No encryption key found', was: ${ex.message}",
        )

        // 4. …and must NOT have minted a key into the vault.
        assertNull(emptyVault.store[alias], "decrypt must not create a key for orphaned ciphertext")
    }

    // ── Construction-time OS-vault unavailability (deep-review #1 & #2) ───────
    //
    // The data-destroying case the runtime-degrade tests above do NOT cover: at
    // construction the OS vault platform exists but its self-test fails for a
    // TRANSIENT reason — a locked macOS Keychain, a Linux login keyring not yet
    // on D-Bus (SSH / headless / session-autostart before unlock). The real
    // keys live in the OS store and it will be reachable on a healthy launch.
    // Pre-fix, pick() silently selected the legacy software store with
    // degraded=false, so (#1) the orphan sweep deleted OS-vault-only ciphertext
    // and (#2) prewarm minted a junk key into the migration source that the next
    // healthy launch then copied OVER the real OS-vault key.

    /** OS-vault stand-in that is unreachable (locked Keychain / keyring down):
     *  every operation throws, so the construction-time self-test fails. */
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
    fun healthyOsCandidate_selectsOsVault_viaSelfTestSeam() {
        // Sanity-check the seam itself: a candidate that PASSES self-test is
        // selected as the active OS vault and nothing is flagged unavailable.
        val fake = FakeOsVault()
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = fake)

        assertFalse(provider.osVaultUnavailable)
        assertFalse(provider.hasDegraded)
        assertEquals(fake, provider.active)
        assertTrue(provider.active.isOsBacked)
    }

    @Test
    fun osVaultUnavailable_refusesToMintKeyIntoLegacyMigrationSource() {
        // Deep-review #2: during an OS-vault-unavailable session, creating a key
        // (the construction-time prewarm of the master alias, or any first
        // encrypted write) must NOT persist key material into the legacy
        // DataStore — that store is the migration source the next healthy launch
        // trusts as authoritative and would copy OVER the real OS-vault key.
        val alias = "user:token"
        val provider = JvmKeyVaultProvider(dataStore, osCandidateForTest = LockedOsVault())
        val engine = JvmSoftwareEncryption(dataStore = dataStore, vaultProvider = provider)

        val ex = assertFailsWith<IllegalStateException> { engine.encrypt(alias, "data".toByteArray()) }
        assertTrue(
            ex.message?.contains("unavailable", ignoreCase = true) == true,
            "key creation while the OS vault is unavailable must fail closed; was: ${ex.message}",
        )
        // The crux: nothing was written into the legacy migration source.
        assertNull(
            DataStoreKeyVault(dataStore).get(alias),
            "no junk key may be minted into the legacy DataStore migration source",
        )
    }

    @Test
    fun osVaultUnavailable_decryptOfUnresolvableKey_reportsUnavailableNotOrphan() {
        // Deep-review #1: a value whose key lives ONLY in the now-unreachable OS
        // vault must report "unavailable", NOT "No encryption key found" — the
        // latter is the message KSafeCore's orphan sweep DELETES on, which would
        // permanently destroy still-recoverable ciphertext.
        val alias = "user:token"

        // Ciphertext produced earlier under a healthy OS vault (in-memory; its
        // key is not present in the legacy DataStore).
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
        // Failing closed must not break the 2.0 upgrade path: when the OS vault
        // is unreachable but a GENUINE pre-2.0 legacy key exists in the
        // DataStore, that key is authoritative and its data must still decrypt —
        // and the key must be left in place (no migration possible) for the next
        // healthy launch to migrate.
        val alias = "settings:theme"
        val payload = "dark".toByteArray()

        // 2.0-style: key + ciphertext live in the legacy DataStore.
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

    // ── Runtime OS-vault unavailability (deep-review #57) ────────────────────
    //
    // The Windows DPAPI / macOS Keychain vaults now map a non-LinkageError runtime lookup
    // failure (DPAPI master-key chain gone / login keychain locked) to the "key vault
    // unavailable" contract instead of leaking a raw Win32Exception/KeychainException. These
    // tests lock in the ENGINE half of that contract via a fake whose get() throws the wording
    // (the platform string-mapping itself needs a real DPAPI/Keychain failure to exercise).

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
        // The vault is unreachable → we can't get OR safely create a key. Fail the write
        // rather than mint a divergent key (which a later healthy launch could treat as
        // authoritative). No put must reach the vault.
        assertFailsWith<IllegalStateException> { engine.encrypt("user:token", "data".toByteArray()) }
        assertFalse(vault.putCalled, "encrypt must fail closed — no key minted into an unavailable vault")
    }

    @Test
    fun degradedVault_decryptOfUnresolvableKey_reportsUnavailableNotOrphan() {
        // Regression for the orphan-sweep data-loss interaction: after a runtime
        // OS-vault LinkageError forces the software fallback, a key that lives
        // ONLY in the now-unreachable OS vault must NOT surface as "No encryption
        // key found" — that is the message KSafeCore's orphan sweep DELETES on.
        // It must report "unavailable", so recoverable ciphertext survives until
        // the OS vault is reachable again.
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

    // ── 2.1.0/2.1.1 → 2.1.2 namespace upgrade recovery (review R6) ──────────
    //
    // Released 2.1.0/2.1.1 derived the default OS-vault namespace from
    // `sun.java.command`; 2.1.2 made it the constant "shared". A stable-launcher
    // app upgrading therefore holds its real keys under the OLD derived
    // namespace — without a read-fallback every decrypt throws "No encryption
    // key found" and the orphan sweep deletes the user's data.

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

        // "2.1.1 install": the key lives under the derived-namespace location.
        val derivedNsVault = FakeOsVault()
        val ciphertextAtRest = JvmSoftwareEncryption(
            dataStore = dataStore,
            vaultProvider = JvmKeyVaultProvider(dataStore, forced = derivedNsVault),
        ).encrypt(alias, payload)
        val realKey = derivedNsVault.store[alias]
        assertNotNull(realKey)

        // "2.1.2 launch": lookups go to the (empty) "shared" namespace; the
        // legacy-namespace twin holds the real key.
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
        // Without a twin (no derived namespace to probe) a miss is a TRUE miss:
        // the orphan-sweep contract ("No encryption key found") must be intact,
        // and the seam-mode provider must never touch a real OS store.
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

    // ── Concurrent self-tests on a shared OS store (review R58) ─────────────

    /**
     * Shared per-user store whose first `put` triggers [onFirstPut] once —
     * simulating another process / instance whose construction-time self-test
     * interleaves with ours on the SAME OS store.
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
        // The OS stores (Keychain / DPAPI / Secret Service) are per-user and
        // shared by every KSafe process/instance. With a FIXED canary alias,
        // a competing self-test's DELETE removed our canary between our put
        // and read-back → our self-test failed → a perfectly healthy vault was
        // flagged unavailable, fail-closing the whole session (review R58).
        //
        // The build runs JVM tests with `-Dksafe.jvm.keyVault=software` (so
        // tests never touch a real keyring); that opt-out short-circuits
        // pick() before the self-test, so lift it for this test and restore.
        val prop = "ksafe.jvm.keyVault"
        val original = System.getProperty(prop)
        System.clearProperty(prop)
        try {
            val shared = RacingOsVault()
            // From inside OUR canary put, a competitor runs its FULL self-test
            // (put + get + delete) against the same shared store.
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
