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
import eu.anifantakis.lib.ksafe.internal.KSafeCore
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

        // Captured before the migration, to prove re-encryption rather than a verbatim copy.
        val srcDefaultCipher = runBlocking {
            val s = newScope()
            val v = (DataStoreJsonStorage(jsonFallback, s).snapshot()[KeySafeMetadataManager.valueRawKey("tokenDefault")] as StoredValue.Text).value
            s.coroutineContext[Job]!!.cancelAndJoin()
            v
        }

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

            val defCipher = (snap[KeySafeMetadataManager.valueRawKey("tokenDefault")] as StoredValue.Text).value
            assertEquals(
                "secret-default",
                targetEngine.decryptSuspend(masterAlias(false), Base64.decode(defCipher)).decodeToString(),
            )
            assertFalse(defCipher == srcDefaultCipher, "ciphertext should change — value was re-encrypted, not copied")

            val hwCipher = (snap[KeySafeMetadataManager.valueRawKey("tokenHw")] as StoredValue.Text).value
            assertEquals(
                "secret-hw",
                targetEngine.decryptSuspend(keyAlias("tokenHw"), Base64.decode(hwCipher)).decodeToString(),
            )

            assertEquals("dark", (snap[KeySafeMetadataManager.valueRawKey("theme")] as StoredValue.Text).value)

            assertEquals(
                KSafeProtection.DEFAULT,
                KeySafeMetadataManager.parseProtection((snap[KeySafeMetadataManager.metadataRawKey("tokenDefault")] as StoredValue.Text).value),
            )
        }

        assertFalse(jsonFallback.exists(), "source JSON should be renamed away")
        assertTrue(File(tmp, "data.ksafe.json.migrated").exists(), "source JSON should be archived")
        assertTrue(File(tmp, "data.ksafe-keys.json.migrated").exists(), "source keys should be archived")
    }

    // A strict-alias-variant entry ("sa":1) must migrate under that same alias formula;
    // probing the bare alias fails its decrypt and silently drops the entry.
    @Test
    fun migrates_strictAliasVariantEntry_underTheVariantAlias() {
        val jsonFallback = File(tmp, "strict.ksafe.json")
        val keysFallback = File(tmp, "strict.ksafe-keys.json")
        val config = KSafeConfig()
        val userKey = "tokenStrict"
        val strictAlias = KSafeCore.strictPerEntryAliasWithGeneration(keyAlias(userKey), 1, null, userKey)

        val srcScope = newScope()
        runBlocking {
            val srcStorage = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            val ct = srcEngine.encryptSuspend(
                identifier = strictAlias,
                data = "secret-strict".encodeToByteArray(),
                hardwareIsolated = true,
                requireUnlockedDevice = true,
            )
            srcStorage.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey(userKey), StoredValue.Text(Base64.encode(ct))),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey(userKey),
                        StoredValue.Text(
                            KeySafeMetadataManager.buildMetadataJson(
                                KSafeProtection.HARDWARE_ISOLATED,
                                accessPolicy = KeySafeMetadataManager.accessPolicyFor(true),
                                strictAliasVariant = true,
                            )
                        ),
                    ),
                )
            )
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }

        val targetScope = newScope()
        val target = DataStoreJsonStorage(File(tmp, "strict-target.json"), targetScope)
        val targetEngine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(File(tmp, "strict-target-keys.json"))),
        )
        migrateJsonFallbackToOsBacked(config, jsonFallback, keysFallback, target, targetEngine, keyAlias, masterAlias)

        runBlocking {
            val snap = target.snapshot()
            val cipher = (snap[KeySafeMetadataManager.valueRawKey(userKey)] as? StoredValue.Text)?.value
            assertTrue(cipher != null, "the strict-variant entry must not be dropped by the migration")
            assertEquals(
                "secret-strict",
                targetEngine.decryptSuspend(strictAlias, Base64.decode(cipher)).decodeToString(),
                "the migrated entry must decrypt under the strict variant alias",
            )
            assertTrue(
                KeySafeMetadataManager.parseStrictAliasVariant(
                    (snap[KeySafeMetadataManager.metadataRawKey(userKey)] as StoredValue.Text).value
                ),
                "the strict-variant marker must be preserved",
            )
        }
        assertTrue(File(tmp, "strict.ksafe.json.migrated").exists(), "source JSON should be archived")
    }

    // A whole-vault source read outage is transient and must block archiving so a healthy launch
    // retries; miscounted as N permanent per-entry skips it archives the fallback into oblivion.
    @Test
    fun wholeVaultSourceReadOutage_blocksArchiving_soMigrationRetries() {
        val jsonFallback = File(tmp, "outage.ksafe.json")
        val keysFallback = File(tmp, "outage.ksafe-keys.json")
        val config = KSafeConfig()

        val srcScope = newScope()
        runBlocking {
            val srcStorage = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            putEncrypted(srcStorage, srcEngine, "tokenDefault", "secret-default", KSafeProtection.DEFAULT)
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }
        assertTrue(keysFallback.exists(), "precondition: the software key file exists")

        // The outage: the key file exists but FileKeyVault.read() throws for it this pass — a
        // transient readText IOException surfaces identically to this unparseable file.
        keysFallback.writeText("{ this is not valid json")

        val targetScope = newScope()
        val target = DataStoreJsonStorage(File(tmp, "outage-target.json"), targetScope)
        val targetEngine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(File(tmp, "outage-target-keys.json"))),
        )
        migrateJsonFallbackToOsBacked(config, jsonFallback, keysFallback, target, targetEngine, keyAlias, masterAlias)

        assertTrue(jsonFallback.exists(), "source JSON must NOT be archived on a whole-vault source read outage")
        assertTrue(keysFallback.exists(), "source keys must NOT be archived on a whole-vault source read outage")
        assertFalse(File(tmp, "outage.ksafe.json.migrated").exists(), "no archive on a transient source outage")
        assertFalse(File(tmp, "outage.ksafe-keys.json.migrated").exists(), "no archive on a transient source outage")
    }

    // A blank keys file is truncation, never a healthy empty vault (FileKeyVault always writes at
    // least "{}"), so it counts as a source outage and blocks archiving.
    @Test
    fun blankKeysFile_countsAsSourceOutage_blocksArchiving_soMigrationRetries() {
        val jsonFallback = File(tmp, "blankout.ksafe.json")
        val keysFallback = File(tmp, "blankout.ksafe-keys.json")
        val config = KSafeConfig()

        val srcScope = newScope()
        runBlocking {
            val srcStorage = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            putEncrypted(srcStorage, srcEngine, "tokenDefault", "secret-default", KSafeProtection.DEFAULT)
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }
        assertTrue(keysFallback.exists(), "precondition: the software key file exists")

        // Truncated to zero bytes (crash mid-write under an old release / external tampering).
        keysFallback.writeText("")

        val targetScope = newScope()
        val target = DataStoreJsonStorage(File(tmp, "blankout-target.json"), targetScope)
        val targetEngine = JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(File(tmp, "blankout-target-keys.json"))),
        )
        migrateJsonFallbackToOsBacked(config, jsonFallback, keysFallback, target, targetEngine, keyAlias, masterAlias)

        assertTrue(jsonFallback.exists(), "source JSON must NOT be archived on a blank keys file")
        assertTrue(keysFallback.exists(), "source keys must NOT be archived on a blank keys file")
        assertFalse(File(tmp, "blankout.ksafe.json.migrated").exists(), "no archive on a truncated keys file")
        assertFalse(File(tmp, "blankout.ksafe-keys.json.migrated").exists(), "no archive on a truncated keys file")
    }

    @Test
    fun realKSafeConstruction_migratesFallbackData_andReadsItBack() {
        // The test JVM has sun.misc.Unsafe, so a real KSafe takes the OS-backed branch and runs
        // the forward migration — this exercises buildJvmKSafe, not just reEncryptAll.
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
            // Encrypted values are JSON-encoded before encryption, so the plaintext bytes
            // for the Int 2024 are those of the JSON literal "2024".
            val ct = engine.encryptSuspend(masterA, "2024".encodeToByteArray())
            storage.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("count2"), StoredValue.Text(Base64.encode(ct))),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("count2"),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
                    ),
                    // A plain String is stored natively — no JSON quotes.
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
        // Toggle case: the fallback is the just-active store, so its value for a key the
        // OS-backed store already holds is the newer one and must win.
        val jsonFallback = File(tmp, "fw.ksafe.json")
        val keysFallback = File(tmp, "fw.ksafe-keys.json")
        val cfg = KSafeConfig()

        val targetScope = newScope()
        val target = DataStoreJsonStorage(File(tmp, "fw-target.json"), targetScope)
        val targetEngine = JvmSoftwareEncryption(
            config = cfg,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(File(tmp, "fw-target-keys.json"))),
        )
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
        // The same precedence as the unit test above, but read back through the public API.
        val baseDir = File(tmp, "ovr").apply { mkdirs() }
        val base = "eu_anifantakis_ksafe_datastore_ovr"
        val cfg = KSafeConfig()

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
        // An orphan must be skipped, not counted as a failure: a failure leaves the source
        // un-archived, so the blocking migration re-runs on every launch.
        val jsonFallback = File(tmp, "orphan.ksafe.json")
        val keysFallback = File(tmp, "orphan.ksafe-keys.json")
        val targetFile = File(tmp, "orphan.preferences.json")
        val config = KSafeConfig()

        // The orphan is the metadata row with no value row beside it.
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

        assertFalse(jsonFallback.exists(), "orphaned metadata must not block archival")
        assertTrue(File(tmp, "orphan.ksafe.json.migrated").exists(), "source should be archived")
        runBlocking {
            assertEquals(
                "dark",
                (target.snapshot()[KeySafeMetadataManager.valueRawKey("theme")] as StoredValue.Text).value,
            )
        }
    }

    @Test
    fun permanentlyUndecryptableEntry_doesNotBlockArchival_andGoodEntryMigrates() {
        // A lost software key is permanent, not retryable, so the pass must still archive —
        // otherwise the blocking migration re-runs every launch.
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
            putEncrypted(src, srcEngine, "good", "v1", KSafeProtection.DEFAULT)
            // Invalid base64 ciphertext — a permanent decrypt failure.
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

        runBlocking {
            val c = (target.snapshot()[KeySafeMetadataManager.valueRawKey("good")] as StoredValue.Text).value
            assertEquals("v1", targetEngine.decryptSuspend(masterAlias(false), Base64.decode(c)).decodeToString())
        }
        // Archiving despite the failure is what stops a re-run from rolling back later writes.
        assertFalse(jsonFallback.exists(), "permanent failure must not block archival")
        assertTrue(File(tmp, "perm.ksafe.json.migrated").exists(), "source must be archived → migration won't re-run")
    }

    /** Target engine whose every encrypt fails as if the OS vault were transiently down. */
    private class TransientFailTargetEngine : KSafeEncryption {
        override fun encrypt(identifier: String, data: ByteArray, hardwareIsolated: Boolean, requireUnlockedDevice: Boolean?,    aad: ByteArray?,): ByteArray =
            throw IllegalStateException("KSafe: OS key vault is unavailable (test transient)")
        override fun decrypt(identifier: String, data: ByteArray, requireUnlockedDevice: Boolean?, aad: ByteArray?): ByteArray =
            throw IllegalStateException("unused")
        override fun deleteKey(identifier: String) {}
    }

    @Test
    fun transientTargetFailure_appliesNothing_andDoesNotArchive_soItRetries() {
        // Writing nothing and archiving nothing keeps the retry a clean full migration,
        // never a partial re-drain that rolls back a newer write.
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
        // A failed attempt leaves the session running on the target, so writes there are newer
        // than the frozen fallback; the `.migration-pending` snapshot is how the retry tells
        // those keys apart from the untouched ones it still has to migrate.
        val jsonFallback = File(tmp, "rt.ksafe.json")
        val keysFallback = File(tmp, "rt.ksafe-keys.json")
        val targetFile = File(tmp, "rt.target.json")
        val targetKeys = File(tmp, "rt.target-keys.json")
        val pendingFile = File(tmp, "rt.ksafe.json.migration-pending")
        val config = KSafeConfig()

        val (target, goodTargetEngine) =
            seedFallbackAndOpenTarget(jsonFallback, keysFallback, targetFile, targetKeys, config)

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
            val sessionCipher = (snap[KeySafeMetadataManager.valueRawKey("session")] as StoredValue.Text).value
            assertEquals(
                "user-fresh",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(sessionCipher)).decodeToString(),
                "the retry must NOT roll a newer target write back to the stale fallback value",
            )
            val themeCipher = (snap[KeySafeMetadataManager.valueRawKey("theme")] as StoredValue.Text).value
            assertEquals(
                "fallback-theme",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(themeCipher)).decodeToString(),
                "keys untouched since the failed attempt must still migrate",
            )
        }
        assertTrue(File(tmp, "rt.ksafe.json.migrated").exists(), "successful retry must archive the source")
        assertFalse(pendingFile.exists(), "successful migration must delete the pending state")
    }

    @Test
    fun retryWithCorruptPendingFile_keepsNewerTargetWrites_insteadOfRollingBack() {
        // The `.migration-pending` file only proves this run is a retry; corrupt, its baseline is
        // unknown, so the safe reading is "keep whatever the target holds", not "fallback wins".
        val jsonFallback = File(tmp, "cp.ksafe.json")
        val keysFallback = File(tmp, "cp.ksafe-keys.json")
        val targetFile = File(tmp, "cp.target.json")
        val targetKeys = File(tmp, "cp.target-keys.json")
        val pendingFile = File(tmp, "cp.ksafe.json.migration-pending")
        val config = KSafeConfig()

        val (target, goodTargetEngine) =
            seedFallbackAndOpenTarget(jsonFallback, keysFallback, targetFile, targetKeys, config)

        // Attempt 1: transient target failure → nothing applied, pending state recorded.
        migrateJsonFallbackToOsBacked(
            config, jsonFallback, keysFallback, target,
            targetEngine = TransientFailTargetEngine(),
            keyAlias = keyAlias, masterAlias = masterAlias,
        )
        assertTrue(pendingFile.exists(), "a transient failure must record the pending state")

        // The session proceeds on the target: the user overwrites "session".
        runBlocking { putEncrypted(target, goodTargetEngine, "session", "user-fresh", KSafeProtection.DEFAULT) }

        // Truncated by process death or a full disk mid-write.
        pendingFile.writeText("{ this is not valid json — truncated")

        // Attempt 2 (next launch): vault healthy → migration runs against the corrupt pending.
        migrateJsonFallbackToOsBacked(
            config, jsonFallback, keysFallback, target,
            targetEngine = goodTargetEngine,
            keyAlias = keyAlias, masterAlias = masterAlias,
        )

        runBlocking {
            val snap = target.snapshot()
            val sessionCipher = (snap[KeySafeMetadataManager.valueRawKey("session")] as StoredValue.Text).value
            assertEquals(
                "user-fresh",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(sessionCipher)).decodeToString(),
                "a corrupt pending file must NOT let the retry roll a newer target write back to the fallback",
            )
            val themeCipher = (snap[KeySafeMetadataManager.valueRawKey("theme")] as StoredValue.Text).value
            assertEquals(
                "fallback-theme",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(themeCipher)).decodeToString(),
                "a key the target lacks still migrates under the conservative retry",
            )
        }
    }

    @Test
    fun pendingMarkerWriteFailure_stillLeavesASentinel_soARetryCannotRollBackNewerWrites() {
        // The pending marker is the only defense against a later launch re-running "fallback
        // wins", so even when its content write fails a 0-byte sentinel must be dropped —
        // without it the next launch overwrites the newer target values with stale ones.
        val jsonFallback = File(tmp, "pw.ksafe.json")
        val keysFallback = File(tmp, "pw.ksafe-keys.json")
        val targetFile = File(tmp, "pw.target.json")
        val targetKeys = File(tmp, "pw.target-keys.json")
        val pendingFile = File(tmp, "pw.ksafe.json.migration-pending")
        val config = KSafeConfig()

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

        // Attempt 1: transient target failure, and the pending-state write itself fails too.
        migrateJsonFallbackToOsBacked(
            config, jsonFallback, keysFallback, target,
            targetEngine = TransientFailTargetEngine(),
            keyAlias = keyAlias, masterAlias = masterAlias,
            persistPendingState = { _, _ -> throw java.io.IOException("injected pending-write failure") },
        )
        assertTrue(pendingFile.exists(), "a failed pending write must still drop a sentinel marker")
        assertEquals(0L, pendingFile.length(), "the last-resort sentinel is a 0-byte proof-of-attempt")

        // The session proceeds on the target: the user overwrites "session".
        runBlocking { putEncrypted(target, goodTargetEngine, "session", "user-fresh", KSafeProtection.DEFAULT) }

        // Attempt 2 (next launch): vault healthy → the sentinel routes to the unknown-retry
        // baseline (keep whatever the target holds; migrate only what it lacks).
        migrateJsonFallbackToOsBacked(
            config, jsonFallback, keysFallback, target,
            targetEngine = goodTargetEngine,
            keyAlias = keyAlias, masterAlias = masterAlias,
        )

        runBlocking {
            val snap = target.snapshot()
            val sessionCipher = (snap[KeySafeMetadataManager.valueRawKey("session")] as StoredValue.Text).value
            assertEquals(
                "user-fresh",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(sessionCipher)).decodeToString(),
                "the sentinel must keep the retry from rolling a newer target write back to stale fallback",
            )
            val themeCipher = (snap[KeySafeMetadataManager.valueRawKey("theme")] as StoredValue.Text).value
            assertEquals(
                "fallback-theme",
                goodTargetEngine.decryptSuspend(masterAlias(false), Base64.decode(themeCipher)).decodeToString(),
                "a key the target lacks still migrates under the conservative retry",
            )
        }
        assertFalse(pendingFile.exists(), "successful migration must clear the sentinel")
    }

    @Test
    fun archiveOrMark_writesDurableSentinel_whenRenameAndCopyBothFail() {
        // The archived JSON fallback is the "already migrated" signal, so when rename and copy
        // both fail a 0-byte sentinel has to stand in — otherwise the gate re-runs the migration
        // and re-drains the stale fallback over newer writes.
        val src = File(tmp, "hc.ksafe.json").apply { writeText("fallback-ciphertext") }
        val marker = File(tmp, "hc.ksafe.json.migrated")
        assertFalse(marker.exists(), "precondition: no marker yet")

        // Rename and copy fail as an AV lock or read-only target would; `touch` stays real,
        // since a migration can always create a file in its own storage directory.
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
        // The copy path must delete the live source the way the rename move would; a lingering
        // plaintext AES key is the whole risk.
        val src = File(tmp, "cf.ksafe-keys.json").apply { writeText("PLAINTEXT-AES-KEY") }
        val marker = File(tmp, "cf.ksafe-keys.json.migrated")

        val marked = archiveOrMark(src, rename = { _, _ -> false }) // copy + delete via real defaults

        assertTrue(marked, "the copy fallback marks the migration done")
        assertTrue(marker.isFile, "the archive copy exists")
        assertFalse(src.exists(), "the live source must be deleted after a copy-fallback (no lingering secret)")
    }

    @Test
    fun archiveOrMark_reportsNotDone_onlyWhenEvenTheSentinelCannotBeWritten() {
        // With not even a sentinel creatable, reporting "not done" is what makes the caller
        // withhold the done-signal and keep the retry-safety pending state.
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
        // A second fallback period writes fresh data behind a `.migrated` marker left by the
        // first. A bare marker-exists gate strands it; the mtime gate sees the newer source.
        val baseDir = File(tmp, "toggle").apply { mkdirs() }
        val base = "eu_anifantakis_ksafe_datastore_toggle"
        val cfg = KSafeConfig()
        val masterA = "toggle:__ksafe_master__"

        val jsonFile = File(baseDir, "$base.ksafe.json")
        val keysFile = File(baseDir, "$base.ksafe-keys.json")

        // Second-period fallback data, seeded as the no-Unsafe path would write it.
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

        // A leftover marker from the first migration, older than the fresh source.
        val marker = File(baseDir, "$base.ksafe.json.migrated").apply { writeText("old-archive") }
        val now = System.currentTimeMillis()
        marker.setLastModified(now - 120_000)
        jsonFile.setLastModified(now)

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

    @Test
    fun appNamespaceAdoption_carriesASecondFallbackPeriodForward() {
        // The same second fallback period, but adopting an appNamespace for the first time: the
        // copy-forward has to preserve source mtimes, or the namespaced gate sees copy-time
        // mtimes, skips the fallback deterministically and strands the data.
        val baseDir = File(tmp, "nsadopt").apply { mkdirs() }
        val base = "eu_anifantakis_ksafe_datastore_nsadopt"
        val cfg = KSafeConfig()
        val masterA = "nsadopt:__ksafe_master__"

        val jsonFile = File(baseDir, "$base.ksafe.json")
        val keysFile = File(baseDir, "$base.ksafe-keys.json")

        // Second-period fallback data seeded as the no-Unsafe path would write it.
        val seedScope = newScope()
        runBlocking {
            val storage = DataStoreJsonStorage(jsonFile, seedScope)
            val engine = JvmSoftwareEncryption(
                config = cfg,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
            )
            val ct = engine.encryptSuspend(masterA, "3333".encodeToByteArray())
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

        // A leftover marker from the first migration, older than the fresh source.
        val marker = File(baseDir, "$base.ksafe.json.migrated").apply { writeText("old-archive") }
        val now = System.currentTimeMillis()
        marker.setLastModified(now - 120_000)
        jsonFile.setLastModified(now)
        keysFile.setLastModified(now)

        // The namespace makes this launch copy the files into a subdir and migrate there.
        val ksafe = KSafe(fileName = "nsadopt", config = KSafeConfig(appNamespace = "nsadoptns"), baseDir = baseDir)
        try {
            runBlocking {
                assertEquals(
                    3333, ksafe.get("count2", 0),
                    "appNamespace adoption must not strand a genuinely-newer fallback period",
                )
            }
        } finally {
            ksafe.close()
        }
        assertTrue(
            File(File(baseDir, "nsadoptns"), "$base.ksafe.json.migrated").exists(),
            "the namespaced migration must have run and archived its source",
        )
    }

    @Test
    fun migrates_rotatedV3Entry_underItsGenerationAliasAndAad_notDropped() {
        val jsonFallback = File(tmp, "rot.ksafe.json")
        val keysFallback = File(tmp, "rot.ksafe-keys.json")
        val targetFile = File(tmp, "rot.preferences.json")
        val targetKeys = File(tmp, "rot.target-keys.json")
        val config = KSafeConfig()
        val storeIdentity = "rotstore"

        // A rotated DEFAULT entry exactly as rotateKeys() leaves it: ".g2" master alias, v3 AAD,
        // metadata stamped v3 / generation 2.
        val srcScope = newScope()
        runBlocking {
            val srcStorage = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            val g2Alias = KSafeCore.aliasWithGeneration(masterAlias(false), 2)
            val aad = KeySafeMetadataManager.aadFor(storeIdentity, "rotKey", KSafeProtection.DEFAULT, false, 2)
            val ct = srcEngine.encryptSuspend(g2Alias, "rotated-secret".encodeToByteArray(), aad = aad)
            srcStorage.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey("rotKey"), StoredValue.Text(Base64.encode(ct))),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey("rotKey"),
                        StoredValue.Text(
                            KeySafeMetadataManager.buildMetadataJson(
                                KSafeProtection.DEFAULT, accessPolicy = null,
                                envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_V3, keyGeneration = 2,
                            )
                        ),
                    ),
                )
            )
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() }

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
            storeIdentity = storeIdentity,
        )

        // The migration once probed the base alias, so the decrypt failed and the entry was
        // silently dropped.
        runBlocking {
            val migratedCt = (target.snapshot()[KeySafeMetadataManager.valueRawKey("rotKey")] as? StoredValue.Text)?.value
            assertTrue(migratedCt != null, "rotated v3 entry must survive the JSON->OS migration")
            val g2Alias = KSafeCore.aliasWithGeneration(masterAlias(false), 2)
            val aad = KeySafeMetadataManager.aadFor(storeIdentity, "rotKey", KSafeProtection.DEFAULT, false, 2)
            val plain = targetEngine.decryptSuspend(g2Alias, Base64.decode(migratedCt!!), aad = aad).decodeToString()
            assertEquals("rotated-secret", plain, "migrated rotated entry must decrypt under its generation alias + AAD")
            targetScope.coroutineContext[Job]!!.cancelAndJoin()
        }
    }

    @Test
    fun migration_carriesTheStoreKeyGeneration_withoutRollingANewerTargetBack() {
        val keygenKey = KeySafeMetadataManager.KEYGEN_RAW_KEY

        fun migrateWithSourceKeygen(name: String, seedTargetKeygen: String?): String? {
            val jsonFallback = File(tmp, "$name.ksafe.json")
            val keysFallback = File(tmp, "$name.ksafe-keys.json")
            val srcScope = newScope()
            runBlocking {
                val srcStorage = DataStoreJsonStorage(jsonFallback, srcScope)
                val srcEngine = JvmSoftwareEncryption(
                    config = KSafeConfig(),
                    vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
                )
                putEncrypted(srcStorage, srcEngine, "k", "v", KSafeProtection.DEFAULT)
                srcStorage.applyBatch(
                    listOf(StorageOp.Put(keygenKey, StoredValue.Text("""{"g":2,"ts":123}""")))
                )
                srcScope.coroutineContext[Job]!!.cancelAndJoin()
            }

            val targetScope = newScope()
            val target = DataStoreJsonStorage(File(tmp, "$name.preferences.json"), targetScope)
            val targetEngine = JvmSoftwareEncryption(
                config = KSafeConfig(),
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(File(tmp, "$name.target-keys.json"))),
            )
            if (seedTargetKeygen != null) {
                runBlocking {
                    target.applyBatch(listOf(StorageOp.Put(keygenKey, StoredValue.Text(seedTargetKeygen))))
                }
            }
            migrateJsonFallbackToOsBacked(
                config = KSafeConfig(),
                jsonFallback = jsonFallback,
                keysFallback = keysFallback,
                target = target,
                targetEngine = targetEngine,
                keyAlias = keyAlias,
                masterAlias = masterAlias,
            )
            return runBlocking {
                val raw = (target.snapshot()[keygenKey] as? StoredValue.Text)?.value
                targetScope.coroutineContext[Job]!!.cancelAndJoin()
                raw
            }
        }

        // Without the record the migrated store regresses to generation 1: the next write drops
        // back to a v2 (no-AAD) envelope and rotation re-targets already-minted aliases.
        assertEquals(
            """{"g":2,"ts":123}""",
            migrateWithSourceKeygen("keygen_fresh", seedTargetKeygen = null),
            "the store key-generation record must migrate with the entry cohort",
        )

        // A target rotated further keeps its record, MaxAge birth timestamp included.
        assertEquals(
            """{"g":3,"ts":50}""",
            migrateWithSourceKeygen("keygen_ahead", seedTargetKeygen = """{"g":3,"ts":50}"""),
            "a newer target generation record must not be rolled back by the migration",
        )
    }

    /**
     * Runs one fallback period — two encrypted keys written through the JSON fallback, then its
     * scope torn down — and opens the OS-backed target over it. The retry tests share this setup.
     */
    private fun seedFallbackAndOpenTarget(
        jsonFallback: File,
        keysFallback: File,
        targetFile: File,
        targetKeys: File,
        config: KSafeConfig,
    ): Pair<DataStoreJsonStorage, JvmSoftwareEncryption> {
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
        return DataStoreJsonStorage(targetFile, targetScope) to JvmSoftwareEncryption(
            config = config,
            vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(targetKeys)),
        )
    }

}
