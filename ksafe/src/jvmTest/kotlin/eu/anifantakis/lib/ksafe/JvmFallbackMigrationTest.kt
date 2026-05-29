package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.DataStoreJsonStorage
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
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
 * Coverage for [migrateJsonFallbackToOsBacked] — the one-time forward migration
 * that runs when an app that persisted through the no-`Unsafe` JSON fallback
 * later starts on the OS-backed DataStore path (e.g. the user added
 * `jdk.unsupported`). Encrypted entries must be **re-encrypted under the new
 * key store** (decryptable by the target engine, not the old one), plain entries
 * copied verbatim, metadata preserved, and the source files archived.
 *
 * Source and target both use [DataStoreJsonStorage] here — the migration is
 * storage-agnostic (it writes via `applyBatch`), so this exercises the
 * re-encryption/re-keying logic without needing the protobuf path. The
 * end-to-end run through a real trimmed-runtime distributable is covered
 * separately (see JSONFILE_FALLBACK_PLAN.md).
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

        // ── 1. Populate the fallback store, then fully release it. ──────────────
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

        // ── 2. Build the OS-backed target + run the migration. ──────────────────
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

        // ── 3. Verify. ──────────────────────────────────────────────────────────
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
        // Seed the fallback files exactly as the no-`Unsafe` path would have, then
        // construct a real KSafe. The test JVM has `sun.misc.Unsafe`, so KSafe
        // takes the OS-backed DataStore branch and runs the forward migration —
        // this exercises the actual buildJvmKSafe wiring, not just reEncryptAll.
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
            // count2: ENCRYPTED Int 2024 (delegates/mutableStateOf encrypt by
            // default). Encrypted values are JSON-encoded before encryption → the
            // plaintext bytes are those of the JSON int literal "2024".
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
        // Reproduces the "toggle modules off, change a value, toggle back on" case
        // (e.g. the count2 counter): the OS-backed store holds a stale value from
        // an earlier migration, and the fallback now has a newer value for that
        // same key PLUS a new key. The fallback was the just-active store, so its
        // values win — the stale key is overwritten and the new key is added.
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
        // The count2 case end-to-end: the OS-backed store already holds a stale
        // value, the fallback holds a fresher one. After re-construction the
        // fresher (just-active) fallback value must win, read back via the API.
        val baseDir = File(tmp, "ovr").apply { mkdirs() }
        val base = "eu_anifantakis_ksafe_datastore_ovr"
        val cfg = KSafeConfig()

        // 1. A real KSafe writes a STALE count2 to the OS-backed store, then closes.
        val k1 = KSafe(fileName = "ovr", baseDir = baseDir)
        runBlocking { k1.put("count2", 2000) }
        k1.close()
        assertTrue(File(baseDir, "$base.preferences_pb").exists())

        // 2. Seed a fallback with a FRESHER count2 (as the no-Unsafe path would).
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

        // 3. Re-construct → migration drains the fallback, overwriting the stale value.
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
}
