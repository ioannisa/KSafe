package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.DataStoreJsonStorage
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.archiveOrMark
import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.migrateJsonFallbackToOsBacked
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: [migrateJsonFallbackToOsBacked] re-encrypts entries under the target key
 * store, copies plain entries verbatim, preserves metadata, and archives the source.
 */
@OptIn(ExperimentalEncodingApi::class)
class JvmFallbackMigrationTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_mig_${System.nanoTime()}")
        .apply { mkdirs() }

    private val scopes = mutableListOf<CoroutineScope>()

    private fun newScope(): CoroutineScope =
        CoroutineScope(Dispatchers.IO + SupervisorJob()).also { scopes += it }

    @AfterTest
    fun tearDown() {
        runBlocking { scopes.forEach { it.coroutineContext[Job]?.cancelAndJoin() } }
        tmp.deleteRecursively()
    }

    private val keyAlias: (String) -> String = { "mig:$it" }
    private val masterAlias: (Boolean) -> String = { "mig:__ksafe_master__" }

    /** Writes an encrypted entry the way KSafeCore would (base64 ciphertext + v2 meta). */
    private suspend fun putEncrypted(
        storage: KSafePlatformStorage,
        engine: KSafeEncryption,
        userKey: String,
        plaintext: String,
        protection: KSafeProtection,
    ) {
        val alias = if (protection == KSafeProtection.DEFAULT) masterAlias(false) else keyAlias(userKey)
        val ct = engine.encryptSuspend(
            identifier = alias,
            data = plaintext.encodeToByteArray(),
            hardwareIsolated = protection == KSafeProtection.HARDWARE_ISOLATED,
        )
        storage.applyBatch(
            listOf(
                StorageOp.Put(KeySafeMetadataManager.valueRawKey(userKey), StoredValue.Text(Base64.encode(ct))),
                StorageOp.Put(
                    KeySafeMetadataManager.metadataRawKey(userKey),
                    StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(protection, accessPolicy = null)),
                ),
            )
        )
    }

    private suspend fun putPlain(storage: KSafePlatformStorage, userKey: String, value: String) {
        storage.applyBatch(
            listOf(
                StorageOp.Put(KeySafeMetadataManager.valueRawKey(userKey), StoredValue.Text(value)),
                StorageOp.Put(
                    KeySafeMetadataManager.metadataRawKey(userKey),
                    StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(protection = null, accessPolicy = null)),
                ),
            )
        )
    }

    @Test
    fun migrates_reEncryptsUnderNewKeyStore_copiesPlain_andArchivesSource() {
        val jsonFallback = File(tmp, "data.ksafe.json")
        val keysFallback = File(tmp, "data.ksafe-keys.json")
        val targetFile = File(tmp, "data.preferences.json")
        val targetKeys = File(tmp, "target.ksafe-keys.json")
        val config = KSafeConfig()

        // Populate the fallback store, then fully release it.
        val srcScope = newScope()
        runBlocking {
            val srcStorage = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            putEncrypted(srcStorage, srcEngine, "tokenDefault", "secret-default", KSafeProtection.DEFAULT)
            putEncrypted(srcStorage, srcEngine, "tokenHw", "secret-hw", KSafeProtection.HARDWARE_ISOLATED)
            putPlain(srcStorage, "theme", "dark")
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() } // release .ksafe.json

        // capture source ciphertext to prove re-encryption (not a verbatim copy)
        val srcDefaultCipher = runBlocking {
            val s = newScope()
            val v = (DataStoreJsonStorage(jsonFallback, s).snapshot()[KeySafeMetadataManager.valueRawKey("tokenDefault")] as StoredValue.Text).value
            s.coroutineContext[Job]!!.cancelAndJoin()
            v
        }

        // Build the OS-backed target + run the migration.
        val targetScope = newScope()
        val target = DataStoreJsonStorage(targetFile, targetScope)
        val targetEngine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(targetKeys)),
        )
        migrateJsonFallbackToOsBacked(
            config = config,
            jsonFallback = jsonFallback,
            keysFallback = keysFallback,
            target = target,
            targetEngine = targetEngine,
            keyAlias = keyAlias,
            masterAlias = masterAlias,
        )

        runBlocking {
            val snap = target.snapshot()

            // DEFAULT entry: decrypts under the TARGET engine (new key) → re-encrypted.
            val defCipher = (snap[KeySafeMetadataManager.valueRawKey("tokenDefault")] as StoredValue.Text).value
            assertEquals(
                "secret-default",
                targetEngine.decryptSuspend(masterAlias(false), Base64.decode(defCipher)).decodeToString(),
            )
            assertFalse(defCipher == srcDefaultCipher, "ciphertext should change — value was re-encrypted, not copied")

            // HARDWARE_ISOLATED entry: decrypts under the per-key alias with the target engine.
            val hwCipher = (snap[KeySafeMetadataManager.valueRawKey("tokenHw")] as StoredValue.Text).value
            assertEquals(
                "secret-hw",
                targetEngine.decryptSuspend(keyAlias("tokenHw"), Base64.decode(hwCipher)).decodeToString(),
            )

            // Plain entry: copied verbatim.
            assertEquals("dark", (snap[KeySafeMetadataManager.valueRawKey("theme")] as StoredValue.Text).value)

            // Metadata preserved (protection literals survive).
            assertEquals(
                KSafeProtection.DEFAULT,
                KeySafeMetadataManager.parseProtection((snap[KeySafeMetadataManager.metadataRawKey("tokenDefault")] as StoredValue.Text).value),
            )
        }

        // Source files archived (renamed), not deleted.
        assertFalse(jsonFallback.exists(), "source JSON should be renamed away")
        assertTrue(File(tmp, "data.ksafe.json.migrated").exists(), "source JSON should be archived")
        assertTrue(File(tmp, "data.ksafe-keys.json.migrated").exists(), "source keys should be archived")
    }

    @Test
    fun realKSafeConstruction_migratesFallbackData_andReadsItBack() {
        // Seed the fallback files as the no-Unsafe path would, then construct a real
        // KSafe: the test JVM has sun.misc.Unsafe, so it takes the OS-backed branch and
        // runs the forward migration (exercising buildJvmKSafe, not just reEncryptAll).
        val baseDir = File(tmp, "real").apply { mkdirs() }
        val base = "eu_anifantakis_ksafe_datastore_testmig"
        val jsonFile = File(baseDir, "$base.ksafe.json")
        val keysFile = File(baseDir, "$base.ksafe-keys.json")
        val cfg = KSafeConfig()
        // fileName="testmig" → KSafeCore aliases are "testmig:<key>" / "testmig:__ksafe_master__".
        val masterA = "testmig:__ksafe_master__"

        val seedScope = newScope()
        runBlocking {
            val storage = DataStoreJsonStorage(jsonFile, seedScope)
            val engine = JvmSoftwareEncryption(
                config = cfg,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
            )
            // count2: encrypted Int 2024 — encrypted values are JSON-encoded before
            // encryption, so the plaintext bytes are those of the JSON literal "2024".
            val ct = engine.encryptSuspend(masterA, "2024".encodeToByteArray())
            storage.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("count2"), StoredValue.Text(Base64.encode(ct))),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("count2"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
                    ),
                    // theme: PLAIN String — primitives are stored natively (no JSON quotes).
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("theme"), StoredValue.Text("dark")),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("theme"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(protection = null, accessPolicy = null)),
                    ),
                )
            )
        }
        runBlocking { seedScope.coroutineContext[Job]!!.cancelAndJoin() } // release .ksafe.json

        val ksafe = KSafe(fileName = "testmig", baseDir = baseDir)
        try {
            runBlocking {
                assertEquals(2024, ksafe.get("count2", 0), "encrypted value migrated + readable")
                assertEquals("dark", ksafe.get("theme", ""), "plain value migrated + readable")
            }
        } finally {
            ksafe.close()
        }

        assertFalse(jsonFile.exists(), "fallback JSON should be archived after migration")
        assertTrue(File(baseDir, "$base.ksafe.json.migrated").exists(), "archive should exist")
        assertTrue(File(baseDir, "$base.preferences_pb").exists(), "OS-backed store should now hold the data")
    }

    @Test
    fun fallbackWins_overwritesExistingKeys_andAddsNewOnes() {
        // Toggle case: the OS-backed store holds a stale value from an earlier migration
        // and the fallback (the just-active store) now has a newer value for that same
        // key plus a new key — the fallback wins, overwriting the stale key.
        val jsonFallback = File(tmp, "fw.ksafe.json")
        val keysFallback = File(tmp, "fw.ksafe-keys.json")
        val cfg = KSafeConfig()

        val targetScope = newScope()
        val target = DataStoreJsonStorage(File(tmp, "fw-target.json"), targetScope)
        val targetEngine = JvmSoftwareEncryption(
            config = cfg,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(File(tmp, "fw-target-keys.json"))),
        )
        // Target holds a STALE "existing" = "stale".
        runBlocking {
            target.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("existing"), StoredValue.Text("stale")),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("existing"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(protection = null, accessPolicy = null)),
                    ),
                )
            )
        }

        // Fallback has the newer "existing" = "fresh" + a new "added".
        val srcScope = newScope()
        runBlocking {
            val src = DataStoreJsonStorage(jsonFallback, srcScope)
            src.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("existing"), StoredValue.Text("fresh")),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("existing"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(protection = null, accessPolicy = null)),
                    ),
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("added"), StoredValue.Text("addedValue")),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("added"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(protection = null, accessPolicy = null)),
                    ),
                )
            )
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }

        migrateJsonFallbackToOsBacked(cfg, jsonFallback, keysFallback, target, targetEngine, keyAlias, masterAlias)

        runBlocking {
            val snap = target.snapshot()
            assertEquals(
                "fresh",
                (snap[KeySafeMetadataManager.valueRawKey("existing")] as StoredValue.Text).value,
                "fallback (just-active store) must overwrite the stale OS-backed value",
            )
            assertEquals(
                "addedValue",
                (snap[KeySafeMetadataManager.valueRawKey("added")] as StoredValue.Text).value,
                "fallback-only key must be added",
            )
        }
        assertTrue(File(tmp, "fw.ksafe.json.migrated").exists(), "clean pass should archive the source")
    }

    @Test
    fun realKSafe_fallbackValueOverwritesStaleOsBackedValue() {
        // End-to-end: the OS-backed store holds a stale value and the fallback a fresher
        // one. After re-construction the fresher fallback value must win, read via the API.
        val baseDir = File(tmp, "ovr").apply { mkdirs() }
        val base = "eu_anifantakis_ksafe_datastore_ovr"
        val cfg = KSafeConfig()

        // A real KSafe writes a stale count2 to the OS-backed store, then closes.
        val k1 = KSafe(fileName = "ovr", baseDir = baseDir)
        runBlocking { k1.put("count2", 2000) }
        k1.close()
        assertTrue(File(baseDir, "$base.preferences_pb").exists())

        // Seed a fallback with a fresher count2 (as the no-Unsafe path would).
        val jsonFile = File(baseDir, "$base.ksafe.json")
        val keysFile = File(baseDir, "$base.ksafe-keys.json")
        val seedScope = newScope()
        runBlocking {
            val storage = DataStoreJsonStorage(jsonFile, seedScope)
            val engine = JvmSoftwareEncryption(
                config = cfg,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
            )
            val ct = engine.encryptSuspend("ovr:__ksafe_master__", "2010".encodeToByteArray())
            storage.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("count2"), StoredValue.Text(Base64.encode(ct))),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("count2"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
                    ),
                )
            )
        }
        runBlocking { seedScope.coroutineContext[Job]!!.cancelAndJoin() }

        // Re-construct → migration drains the fallback, overwriting the stale value.
        val k2 = KSafe(fileName = "ovr", baseDir = baseDir)
        try {
            runBlocking {
                assertEquals(2010, k2.get("count2", 0), "fresher fallback value must overwrite the stale OS-backed one")
            }
        } finally {
            k2.close()
        }
        assertTrue(File(baseDir, "$base.ksafe.json.migrated").exists())
    }

    @Test
    fun noFallbackData_isNoOp() {
        // Calling with a non-existent source must not throw and must not create files.
        val jsonFallback = File(tmp, "absent.ksafe.json")
        val keysFallback = File(tmp, "absent.ksafe-keys.json")
        val targetScope = newScope()
        val target = DataStoreJsonStorage(File(tmp, "t.json"), targetScope)
        val engine = JvmSoftwareEncryption(
            config = KSafeConfig(),
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
        )
        // Source missing → reEncryptAll sees an empty snapshot; archive renames are no-ops.
        migrateJsonFallbackToOsBacked(
            config = KSafeConfig(),
            jsonFallback = jsonFallback,
            keysFallback = keysFallback,
            target = target,
            targetEngine = engine,
            keyAlias = keyAlias,
            masterAlias = masterAlias,
        )
        runBlocking { assertTrue(target.snapshot().isEmpty()) }
    }

    @Test
    fun orphanedEncryptedMetadata_doesNotBlockArchival() {
        // An encrypted-metadata row whose value row is gone (orphaned) must be skipped,
        // not counted as a failure — a failure leaves the source un-archived, so the
        // blocking migration would re-run on every launch.
        val jsonFallback = File(tmp, "orphan.ksafe.json")
        val keysFallback = File(tmp, "orphan.ksafe-keys.json")
        val targetFile = File(tmp, "orphan.preferences.json")
        val config = KSafeConfig()

        // Seed: one good plain entry + an ORPHANED encrypted entry (metadata only,
        // no value row). Then release the source handle.
        val srcScope = newScope()
        runBlocking {
            val src = DataStoreJsonStorage(jsonFallback, srcScope)
            putPlain(src, "theme", "dark")
            src.applyBatch(
                listOf(
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("ghost"),
                        StoredValue.Text(
                            KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)
                        ),
                    ),
                )
            )
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }

        val targetScope = newScope()
        val target = DataStoreJsonStorage(targetFile, targetScope)
        migrateJsonFallbackToOsBacked(
            config = config,
            jsonFallback = jsonFallback,
            keysFallback = keysFallback,
            target = target,
            targetEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(File(tmp, "orphan.target-keys.json"))),
            ),
            keyAlias = keyAlias,
            masterAlias = masterAlias,
        )

        // Clean pass despite the orphan → source archived (orphan skipped, not failed).
        assertFalse(jsonFallback.exists(), "orphaned metadata must not block archival")
        assertTrue(File(tmp, "orphan.ksafe.json.migrated").exists(), "source should be archived")
        // The good plain entry still migrated.
        runBlocking {
            assertEquals(
                "dark",
                (target.snapshot()[KeySafeMetadataManager.valueRawKey("theme")] as StoredValue.Text).value,
            )
        }
    }

    @Test
    fun permanentlyUndecryptableEntry_doesNotBlockArchival_andGoodEntryMigrates() {
        // An entry whose ciphertext can't be decrypted (corrupt/lost software key) is a
        // permanent failure — it must be skipped, not treated as retryable, so a pass
        // still archives and the blocking migration doesn't re-run every launch.
        val jsonFallback = File(tmp, "perm.ksafe.json")
        val keysFallback = File(tmp, "perm.ksafe-keys.json")
        val targetFile = File(tmp, "perm.target.json")
        val config = KSafeConfig()

        val srcScope = newScope()
        runBlocking {
            val src = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            // A good DEFAULT entry that decrypts cleanly under the source key.
            putEncrypted(src, srcEngine, "good", "v1", KSafeProtection.DEFAULT)
            // A corrupt DEFAULT entry: invalid base64 ciphertext → permanent decrypt failure.
            src.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("bad"), StoredValue.Text("@@@not-base64@@@")),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("bad"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
                    ),
                )
            )
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }

        val targetScope = newScope()
        val target = DataStoreJsonStorage(targetFile, targetScope)
        val targetEngine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(File(tmp, "perm.target-keys.json"))),
        )
        migrateJsonFallbackToOsBacked(config, jsonFallback, keysFallback, target, targetEngine, keyAlias, masterAlias)

        // The good entry migrated…
        runBlocking {
            val c = (target.snapshot()[KeySafeMetadataManager.valueRawKey("good")] as StoredValue.Text).value
            assertEquals("v1", targetEngine.decryptSuspend(masterAlias(false), Base64.decode(c)).decodeToString())
        }
        // …and the source is archived despite the permanent failure, so the gate won't
        // re-run the migration and roll back the user's later writes to "good".
        assertFalse(jsonFallback.exists(), "permanent failure must not block archival")
        assertTrue(File(tmp, "perm.ksafe.json.migrated").exists(), "source must be archived → migration won't re-run")
    }

    /** Target engine whose every encrypt fails as if the OS vault were transiently down. */
    private class TransientFailTargetEngine : KSafeEncryption {
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?): ByteArray =
            throw IllegalStateException("KSafe: OS key vault is unavailable (test transient)")
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?): ByteArray =
            throw IllegalStateException("unused")
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun transientTargetFailure_appliesNothing_andDoesNotArchive_soItRetries() {
        // A transient target-vault failure must abort the whole migration this launch —
        // write nothing, archive nothing — so the retry next launch is a clean full
        // migration, never a partial re-drain that rolls back a newer write.
        val jsonFallback = File(tmp, "tr.ksafe.json")
        val keysFallback = File(tmp, "tr.ksafe-keys.json")
        val targetFile = File(tmp, "tr.target.json")
        val config = KSafeConfig()

        val srcScope = newScope()
        runBlocking {
            val src = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            putEncrypted(src, srcEngine, "good", "v1", KSafeProtection.DEFAULT)
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }

        val targetScope = newScope()
        val target = DataStoreJsonStorage(targetFile, targetScope)
        migrateJsonFallbackToOsBacked(
            config, jsonFallback, keysFallback, target,
            targetEngine = TransientFailTargetEngine(),
            keyAlias = keyAlias, masterAlias = masterAlias,
        )

        runBlocking {
            assertFalse(
                target.snapshot().containsKey(KeySafeMetadataManager.valueRawKey("good")),
                "a transient target failure must apply NOTHING (no partial drain)",
            )
        }
        assertTrue(jsonFallback.exists(), "transient failure must NOT archive — the source stays for a clean retry")
        assertFalse(File(tmp, "tr.ksafe.json.migrated").exists(), "no marker on transient failure")
    }

    @Test
    fun retryAfterTransientFailure_keepsNewerTargetWrites_andStillMigratesUntouchedKeys() {
        // A transiently-failed migration leaves the session running on the OS-backed
        // target, so writes there are newer than the frozen fallback. The retry must skip
        // keys the user wrote after the failed attempt (tracked via the `.migration-pending`
        // snapshot) so it doesn't roll them back, while still migrating untouched keys.
        val jsonFallback = File(tmp, "rt.ksafe.json")
        val keysFallback = File(tmp, "rt.ksafe-keys.json")
        val targetFile = File(tmp, "rt.target.json")
        val targetKeys = File(tmp, "rt.target-keys.json")
        val pendingFile = File(tmp, "rt.ksafe.json.migration-pending")
        val config = KSafeConfig()

        // Fallback period: two keys live in the fallback store.
        val srcScope = newScope()
        runBlocking {
            val src = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            putEncrypted(src, srcEngine, "session", "fallback-session", KSafeProtection.DEFAULT)
            putEncrypted(src, srcEngine, "theme", "fallback-theme", KSafeProtection.DEFAULT)
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }

        val targetScope = newScope()
        val target = DataStoreJsonStorage(targetFile, targetScope)
        val goodTargetEngine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(targetKeys)),
        )

        // Attempt 1: transient target failure → nothing applied, pending state recorded.
        migrateJsonFallbackToOsBacked(
            config, jsonFallback, keysFallback, target,
            targetEngine = TransientFailTargetEngine(),
            keyAlias = keyAlias, masterAlias = masterAlias,
        )
        assertTrue(pendingFile.exists(), "a transient failure must record the target's pending state")

        // The session proceeds on the target: the user overwrites "session".
        runBlocking { putEncrypted(target, goodTargetEngine, "session", "user-fresh", KSafeProtection.DEFAULT) }

        // Attempt 2 (next launch): vault healthy → migration succeeds.
        migrateJsonFallbackToOsBacked(
            config, jsonFallback, keysFallback, target,
            targetEngine = goodTargetEngine,
            keyAlias = keyAlias, masterAlias = masterAlias,
        )

        runBlocking {
            val snap = target.snapshot()
            // The user's post-attempt write must survive the retry…
            val sessionCipher = (snap[KeySafeMetadataManager.valueRawKey("session")] as StoredValue.Text).value
            assertEquals(
                "user-fresh",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(sessionCipher)).decodeToString(),
                "the retry must NOT roll a newer target write back to the stale fallback value",
            )
            // …while a key untouched since the failed attempt still migrates.
            val themeCipher = (snap[KeySafeMetadataManager.valueRawKey("theme")] as StoredValue.Text).value
            assertEquals(
                "fallback-theme",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(themeCipher)).decodeToString(),
                "keys untouched since the failed attempt must still migrate",
            )
        }
        // Successful migration archives the sources and clears the pending state.
        assertTrue(File(tmp, "rt.ksafe.json.migrated").exists(), "successful retry must archive the source")
        assertFalse(pendingFile.exists(), "successful migration must delete the pending state")
    }

    @Test
    fun retryWithCorruptPendingFile_keepsNewerTargetWrites_insteadOfRollingBack() {
        // The `.migration-pending` file proves this run is a retry. Present-but-corrupt
        // (a partial write from process death / full disk) must still be treated as a
        // retry with an unknown baseline — conservatively keep any value the target holds,
        // rather than reverting to "fallback wins" and rolling back newer writes.
        val jsonFallback = File(tmp, "cp.ksafe.json")
        val keysFallback = File(tmp, "cp.ksafe-keys.json")
        val targetFile = File(tmp, "cp.target.json")
        val targetKeys = File(tmp, "cp.target-keys.json")
        val pendingFile = File(tmp, "cp.ksafe.json.migration-pending")
        val config = KSafeConfig()

        // Fallback period: two keys live in the fallback store.
        val srcScope = newScope()
        runBlocking {
            val src = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            putEncrypted(src, srcEngine, "session", "fallback-session", KSafeProtection.DEFAULT)
            putEncrypted(src, srcEngine, "theme", "fallback-theme", KSafeProtection.DEFAULT)
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }

        val targetScope = newScope()
        val target = DataStoreJsonStorage(targetFile, targetScope)
        val goodTargetEngine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(targetKeys)),
        )

        // Attempt 1: transient target failure → nothing applied, pending state recorded.
        migrateJsonFallbackToOsBacked(
            config, jsonFallback, keysFallback, target,
            targetEngine = TransientFailTargetEngine(),
            keyAlias = keyAlias, masterAlias = masterAlias,
        )
        assertTrue(pendingFile.exists(), "a transient failure must record the pending state")

        // The session proceeds on the target: the user overwrites "session".
        runBlocking { putEncrypted(target, goodTargetEngine, "session", "user-fresh", KSafeProtection.DEFAULT) }

        // The pending file is left CORRUPT (truncated / partial write).
        pendingFile.writeText("{ this is not valid json — truncated")

        // Attempt 2 (next launch): vault healthy → migration runs against the corrupt pending.
        migrateJsonFallbackToOsBacked(
            config, jsonFallback, keysFallback, target,
            targetEngine = goodTargetEngine,
            keyAlias = keyAlias, masterAlias = masterAlias,
        )

        runBlocking {
            val snap = target.snapshot()
            // The user's post-attempt write must survive — NOT be rolled back to the fallback.
            val sessionCipher = (snap[KeySafeMetadataManager.valueRawKey("session")] as StoredValue.Text).value
            assertEquals(
                "user-fresh",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(sessionCipher)).decodeToString(),
                "a corrupt pending file must NOT let the retry roll a newer target write back to the fallback",
            )
            // A key absent in the target still migrates from the fallback.
            val themeCipher = (snap[KeySafeMetadataManager.valueRawKey("theme")] as StoredValue.Text).value
            assertEquals(
                "fallback-theme",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(themeCipher)).decodeToString(),
                "a key the target lacks still migrates under the conservative retry",
            )
        }
    }

    @Test
    fun archiveOrMark_writesDurableSentinel_whenRenameAndCopyBothFail() {
        // The migration archives the JSON fallback as the "already migrated" signal. If
        // both the rename AND the copy fail (permissions / AV lock / disk full), a failed
        // archive must still leave a durable 0-byte sentinel so the file-based gate won't
        // re-run the migration and re-drain the stale fallback over newer writes.
        val src = File(tmp, "hc.ksafe.json").apply { writeText("fallback-ciphertext") }
        val marker = File(tmp, "hc.ksafe.json.migrated")
        assertFalse(marker.exists(), "precondition: no marker yet")

        // Force rename + copy to fail (as an AV lock / read-only-target would);
        // the real `touch` (createNewFile) stands in for the 0-byte sentinel a
        // successful migration can always write into its own storage directory.
        val marked = archiveOrMark(
            src,
            rename = { _, _ -> false },
            copy = { _, _ -> false },
        )

        assertTrue(marked, "archiveOrMark must report the migration durably marked done")
        assertTrue(marker.isFile, "a failed archive must still leave a durable .migrated sentinel")
    }

    @Test
    fun archiveOrMark_copyFallback_deletesTheLiveSource() {
        // When rename fails but copy succeeds, the live source (plaintext AES key /
        // ciphertext) must not linger — the copy path deletes it, mirroring the rename move.
        val src = File(tmp, "cf.ksafe-keys.json").apply { writeText("PLAINTEXT-AES-KEY") }
        val marker = File(tmp, "cf.ksafe-keys.json.migrated")

        val marked = archiveOrMark(src, rename = { _, _ -> false }) // copy + delete via real defaults

        assertTrue(marked, "the copy fallback marks the migration done")
        assertTrue(marker.isFile, "the archive copy exists")
        assertFalse(src.exists(), "the live source must be deleted after a copy-fallback (no lingering secret)")
    }

    @Test
    fun archiveOrMark_reportsNotDone_onlyWhenEvenTheSentinelCannotBeWritten() {
        // A fully unwritable directory where not even a 0-byte sentinel can be created:
        // archiveOrMark must report "not done" so the caller withholds the done-signal
        // and keeps the retry-safety pending state.
        val src = File(tmp, "hc2.ksafe.json").apply { writeText("fallback-ciphertext") }
        val marked = archiveOrMark(
            src,
            rename = { _, _ -> false },
            copy = { _, _ -> false },
            touch = { false },
        )
        assertFalse(marked, "with no marker creatable at all, the migration must not be reported done")
    }

    @Test
    fun secondFallbackPeriod_freshDataMigrates_despiteOldMarker() {
        // Toggle case: after a first migration leaves a permanent `.migrated` marker, a
        // second fallback period writes fresh data. A bare marker-exists gate would strand
        // it; the mtime gate migrates it because the live source is newer than the marker.
        val baseDir = File(tmp, "toggle").apply { mkdirs() }
        val base = "eu_anifantakis_ksafe_datastore_toggle"
        val cfg = KSafeConfig()
        val masterA = "toggle:__ksafe_master__"

        val jsonFile = File(baseDir, "$base.ksafe.json")
        val keysFile = File(baseDir, "$base.ksafe-keys.json")

        // Second-period fallback data ("v2") seeded as the no-Unsafe path would write it.
        val seedScope = newScope()
        runBlocking {
            val storage = DataStoreJsonStorage(jsonFile, seedScope)
            val engine = JvmSoftwareEncryption(
                config = cfg,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
            )
            val ct = engine.encryptSuspend(masterA, "2222".encodeToByteArray())
            storage.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("count2"), StoredValue.Text(Base64.encode(ct))),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("count2"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
                    ),
                )
            )
        }
        runBlocking { seedScope.coroutineContext[Job]!!.cancelAndJoin() }

        // A leftover marker from a FIRST migration, older than the fresh second-period source.
        val marker = File(baseDir, "$base.ksafe.json.migrated").apply { writeText("old-archive") }
        val now = System.currentTimeMillis()
        marker.setLastModified(now - 120_000)
        jsonFile.setLastModified(now)

        // Modules restored → OS-backed construction must migrate the fresh data forward.
        val ksafe = KSafe(fileName = "toggle", baseDir = baseDir)
        try {
            runBlocking {
                assertEquals(
                    2222, ksafe.get("count2", 0),
                    "second-period fallback data must carry forward despite an old .migrated marker",
                )
            }
        } finally {
            ksafe.close()
        }
    }
}
