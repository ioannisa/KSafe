package eu.anifantakis.lib.ksafe

import android.content.Context
import android.util.Base64
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.DataStoreDekStore
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Locks in: the Android software-DEK fast path — relaxed DEFAULT entries wrap a userspace DEK while strict/hardware-isolated writes stay on the per-call TEE path, legacy TEE ciphertext survives the upgrade, and DEK self-heal/regeneration never lose acknowledged writes. */
@RunWith(AndroidJUnit4::class)
class AndroidSoftwareDekTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    // "KSD1" — must match AndroidKeystoreEncryption.DEK_MAGIC.
    private val magic = byteArrayOf(0x4B, 0x53, 0x44, 0x31)

    private val scopes = mutableListOf<CoroutineScope>()
    private val files = mutableListOf<File>()

    @After
    fun tearDown() {
        scopes.forEach { runCatching { it.cancel() } }
        files.forEach { runCatching { it.delete() } }
    }

    private var counter = 0
    private fun uniqueAlias(): String {
        counter++
        return "ksafe_dektest_${System.nanoTime()}_$counter"
    }

    /** A fresh, isolated DataStore-backed storage (its own file + scope) per call. */
    private fun newStorage(): DataStoreStorage {
        counter++
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        scopes += scope
        val file = File(context.cacheDir, "dektest_${System.nanoTime()}_$counter.preferences_pb")
        files += file
        return DataStoreStorage(PreferenceDataStoreFactory.create(scope = scope) { file })
    }

    private fun engine(storage: DataStoreStorage, useSoftwareDek: Boolean = true) =
        AndroidKeystoreEncryption(
            config = KSafeConfig(),
            dekStore = DataStoreDekStore(storage),
            useSoftwareDek = useSoftwareDek,
        )

    private fun dekPresent(storage: DataStoreStorage): Boolean =
        runBlocking { storage.snapshot().containsKey(DataStoreDekStore.DEK_KEY) }

    private fun ByteArray.startsWithMagic(): Boolean =
        size >= magic.size && magic.indices.all { this[it] == magic[it] }

    @Test
    fun relaxedDefault_roundTrips_andProducesDekHeader_andDekEntry() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val e = engine(storage)
        try {
            val plain = "super-secret-token-value".encodeToByteArray()
            val blob = e.encrypt(alias, plain, hardwareIsolated = false, requireUnlockedDevice = false)

            assertTrue(blob.startsWithMagic(), "relaxed DEFAULT blob should carry the DEK header")
            assertTrue(dekPresent(storage), "a wrapped DEK should be persisted in the DataStore")
            assertContentEquals(plain, e.decrypt(alias, blob), "DEK round-trip must return the original")
        } finally {
            e.deleteKey(alias)
        }
    }

    /** Legacy TEE ciphertext (written before the DEK path) must stay decryptable, and new DEK writes coexist with it. */
    @Test
    fun crossVersion_legacyTeeBlob_staysReadable_andNewDekBlobCoexists() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val legacy = engine(storage, useSoftwareDek = false)
        val upgraded = engine(storage, useSoftwareDek = true)
        try {
            val oldPlain = "legacy-tee-value".encodeToByteArray()
            val legacyBlob = legacy.encrypt(alias, oldPlain, hardwareIsolated = false, requireUnlockedDevice = false)
            assertFalse(legacyBlob.startsWithMagic(), "legacy TEE blob must NOT carry the DEK header")

            assertContentEquals(oldPlain, upgraded.decrypt(alias, legacyBlob), "legacy data must survive the upgrade")

            val newPlain = "fresh-dek-value".encodeToByteArray()
            val dekBlob = upgraded.encrypt(alias, newPlain, hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekBlob.startsWithMagic(), "post-upgrade write should use the DEK header")
            assertContentEquals(newPlain, upgraded.decrypt(alias, dekBlob))
            assertContentEquals(oldPlain, upgraded.decrypt(alias, legacyBlob))
        } finally {
            upgraded.deleteKey(alias)
        }
    }

    @Test
    fun lockedVariant_staysTee_noMagic_noDekEntry() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val e = engine(storage)
        try {
            val plain = "locked-master-value".encodeToByteArray()
            // requireUnlockedDevice = true forces the strict TEE path — never the DEK branch.
            val blob = e.encrypt(alias, plain, hardwareIsolated = false, requireUnlockedDevice = true)
            assertFalse(blob.startsWithMagic(), "locked variant must stay on the TEE path (no DEK header)")
            assertFalse(dekPresent(storage), "locked variant must not persist a DEK")
            assertContentEquals(plain, e.decrypt(alias, blob))
        } finally {
            e.deleteKey(alias)
        }
    }

    @Test
    fun hardwareIsolated_staysTee_noMagic_noDekEntry() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val e = engine(storage)
        try {
            val plain = "hardware-isolated-value".encodeToByteArray()
            val blob = e.encrypt(alias, plain, hardwareIsolated = true, requireUnlockedDevice = false)
            assertFalse(blob.startsWithMagic(), "HARDWARE_ISOLATED must stay on the TEE path (no DEK header)")
            assertFalse(dekPresent(storage), "HARDWARE_ISOLATED must not persist a DEK")
            assertContentEquals(plain, e.decrypt(alias, blob))
        } finally {
            e.deleteKey(alias)
        }
    }

    @Test
    fun deleteKey_removesKek_andSubsequentDecryptThrowsNoKeyFound() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val e = engine(storage)
        val plain = "to-be-deleted".encodeToByteArray()
        val blob = e.encrypt(alias, plain, hardwareIsolated = false, requireUnlockedDevice = false)
        assertTrue(dekPresent(storage))

        // deleteKey removes the master KEK; the wrapped DEK lingers (fixed per-safe storage key)
        // but can no longer be unwrapped, so a cold engine's decrypt fails definitively.
        e.deleteKey(alias)

        val fresh = engine(storage)
        val ex = assertFails { fresh.decrypt(alias, blob) }
        assertTrue(
            ex.message?.contains("No encryption key found", ignoreCase = true) == true,
            "a deleted KEK must surface the canonical no-key message for orphan reclamation, was: ${ex.message}"
        )
    }

    @Test
    fun missingDek_outOfBand_throwsNoKeyFound() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val e = engine(storage)
        try {
            val blob = e.encrypt(alias, "v".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            // Simulate the wrapped DEK going missing (e.g. cleared storage) while the KEK lingers.
            runBlocking { storage.applyBatch(listOf(StorageOp.Delete(DataStoreDekStore.DEK_KEY))) }
            val fresh = engine(storage)
            val ex = assertFails { fresh.decrypt(alias, blob) }
            assertTrue(ex.message?.contains("No encryption key found", ignoreCase = true) == true)
        } finally {
            e.deleteKey(alias)
        }
    }

    @Test
    fun concurrentFirstWrites_generateSingleDek_andAllRoundTrip() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val e = engine(storage)
        try {
            val n = 32
            val blobs = runBlocking(Dispatchers.Default) {
                (0 until n).map { i ->
                    async {
                        e.encrypt(alias, "value_$i".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
                    }
                }.awaitAll()
            }
            assertTrue(dekPresent(storage))
            blobs.forEachIndexed { i, blob ->
                assertTrue(blob.startsWithMagic())
                assertEquals("value_$i", e.decrypt(alias, blob).decodeToString())
            }
        } finally {
            e.deleteKey(alias)
        }
    }

    /** A corrupt wrapped DEK must self-heal: the next encrypt regenerates a fresh DEK + KEK rather than failing writes forever. */
    @Test
    fun corruptWrappedDek_selfHealsOnNextEncrypt() {
        val storage = newStorage()
        val e = engine(storage)
        val master = uniqueAlias()
        try {
            e.encrypt(master, "first".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))

            // Overwrite the stored wrapped DEK with garbage that fails GCM auth under the KEK.
            runBlocking {
                storage.applyBatch(
                    listOf(
                        StorageOp.Put(
                            DataStoreDekStore.DEK_KEY,
                            StoredValue.Text(Base64.encodeToString(ByteArray(40) { 0x7 }, Base64.NO_WRAP)),
                        )
                    )
                )
            }

            val fresh = engine(storage)
            val blob = fresh.encrypt(master, "after".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(blob.startsWithMagic(), "self-healed write should use the DEK header")
            assertContentEquals(
                "after".encodeToByteArray(),
                fresh.decrypt(master, blob),
                "regenerated DEK must encrypt/decrypt new data",
            )
        } finally {
            e.deleteKey(master)
        }
    }

    /** Concurrent regeneration must be atomic: writers that all read the same corrupt DEK regenerate concurrently, and no sibling's freshly-minted (already-written-under) DEK may be discarded — exactly one DEK survives and every blob still decrypts. */
    @Test
    fun concurrentRegenerate_doesNotDiscardAnotherWritersFreshDek() {
        val storage = newStorage()
        val master = uniqueAlias()
        val seed = engine(storage)
        try {
            // Establish a DEK, then corrupt it so every cold-engine unwrap fails into regenerateDek.
            seed.encrypt(master, "seed".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))
            runBlocking {
                storage.applyBatch(
                    listOf(
                        StorageOp.Put(
                            DataStoreDekStore.DEK_KEY,
                            StoredValue.Text(Base64.encodeToString(ByteArray(40) { 0x7 }, Base64.NO_WRAP)),
                        )
                    )
                )
            }

            val fresh = engine(storage)
            val n = 16
            val blobs = runBlocking(Dispatchers.Default) {
                (0 until n).map { i ->
                    async {
                        i to fresh.encrypt(
                            master, "value_$i".encodeToByteArray(),
                            hardwareIsolated = false, requireUnlockedDevice = false,
                        )
                    }
                }.awaitAll()
            }

            blobs.forEach { (i, blob) ->
                assertTrue(blob.startsWithMagic(), "regenerated write should use the DEK header")
                assertContentEquals(
                    "value_$i".encodeToByteArray(),
                    fresh.decrypt(master, blob),
                    "every concurrently-regenerated write must remain decryptable",
                )
            }
        } finally {
            seed.deleteKey(master)
        }
    }

    /** A corrupt-DEK self-heal must mint a fresh DEK under the SAME healthy KEK, never deleting the KEK — or legacy TEE ciphertext encrypted directly under it would be destroyed. */
    @Test
    fun corruptDek_selfHeals_withoutDestroyingLegacyTeeCiphertextUnderSameKek() {
        val storage = newStorage()
        val master = uniqueAlias()
        try {
            // Legacy TEE blob encrypted DIRECTLY under the master KEK (DEK off).
            val legacy = engine(storage, useSoftwareDek = false)
            val legacyBlob = legacy.encrypt(master, "legacy-value".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertFalse(legacyBlob.startsWithMagic(), "precondition: legacy TEE blob has no DEK header")

            val dekEngine = engine(storage, useSoftwareDek = true)
            dekEngine.encrypt(master, "dek-value".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))

            // Corrupt the wrapped DEK (fails GCM auth) — the KEK stays fine.
            runBlocking {
                storage.applyBatch(
                    listOf(
                        StorageOp.Put(
                            DataStoreDekStore.DEK_KEY,
                            StoredValue.Text(Base64.encodeToString(ByteArray(40) { 0x7 }, Base64.NO_WRAP)),
                        )
                    )
                )
            }

            val fresh = engine(storage, useSoftwareDek = true)
            val healed = fresh.encrypt(master, "after".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertContentEquals("after".encodeToByteArray(), fresh.decrypt(master, healed), "regenerated DEK must round-trip")

            assertContentEquals(
                "legacy-value".encodeToByteArray(),
                fresh.decrypt(master, legacyBlob),
                "legacy TEE ciphertext under the same KEK must survive a corrupt-DEK self-heal",
            )
        } finally {
            engine(storage).deleteKey(master)
        }
    }

    /** A wrapped DEK present with its KEK absent (Auto Backup restored the DataStore to a device with an empty Keystore) must self-heal on the next encrypt, not brick every write. */
    @Test
    fun wrappedDekPresent_butKekAbsent_selfHealsOnEncrypt() {
        val storage = newStorage()
        val master = uniqueAlias()
        val e = engine(storage)
        try {
            e.encrypt(master, "v1".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))

            // deleteKey removes the KEK but leaves the wrapped DEK (fixed per-safe storage key)
            // — the restored-DataStore + empty-Keystore state.
            e.deleteKey(master)
            assertTrue(dekPresent(storage), "precondition: wrapped DEK still present after KEK deletion")

            val fresh = engine(storage)
            val healed = fresh.encrypt(master, "v2".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(healed.startsWithMagic())
            assertContentEquals(
                "v2".encodeToByteArray(),
                fresh.decrypt(master, healed),
                "encrypt must self-heal when the KEK is absent but a wrapped DEK lingers",
            )
        } finally {
            engine(storage).deleteKey(master)
        }
    }

    /** A malformed wrapped-DEK entry (invalid Base64 / too short for the GCM IV) must self-heal like the corrupt-but-well-formed case, not brick encrypted writes. */
    @Test
    fun malformedWrappedDek_selfHealsOnEncrypt() {
        val storage = newStorage()
        val master = uniqueAlias()
        val e = engine(storage)
        try {
            e.encrypt(master, "v1".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))

            // Invalid Base64 → load() throws IllegalArgumentException (not AEADBadTagException);
            // the self-heal must catch this shape too.
            runBlocking {
                storage.applyBatch(
                    listOf(StorageOp.Put(DataStoreDekStore.DEK_KEY, StoredValue.Text("@@@not-valid-base64@@@")))
                )
            }

            val fresh = engine(storage)
            val healed = fresh.encrypt(master, "v2".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(healed.startsWithMagic())
            assertContentEquals(
                "v2".encodeToByteArray(),
                fresh.decrypt(master, healed),
                "a malformed wrapped DEK must self-heal on the next encrypt",
            )
        } finally {
            engine(storage).deleteKey(master)
        }
    }

    /** Lazy DEK: prewarm warms only the wrapping KEK and must NOT persist a DEK — it appears on the first real encrypt, so an unencrypted-only safe never writes one. */
    @Test
    fun prewarmKey_doesNotPersistDek_butFirstEncryptDoes() {
        val storage = newStorage()
        val e = engine(storage)
        val master = uniqueAlias()
        try {
            runBlocking { e.prewarmKey(master, hardwareIsolated = false, requireUnlockedDevice = false) }
            assertFalse(dekPresent(storage), "prewarm must NOT persist a DEK (created lazily on first encrypt)")

            e.encrypt(master, "v".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage), "the first real encrypt must persist the DEK")
        } finally {
            e.deleteKey(master)
        }
    }

    /** The per-safe DEK has ONE storage key, so deleting an unrelated (per-entry / HARDWARE_ISOLATED) key must never remove it — or every relaxed DEFAULT value would be bricked. */
    @Test
    fun deleteUnrelatedKey_doesNotRemoveSharedDek() {
        val storage = newStorage()
        val master = uniqueAlias()
        val e = engine(storage)
        try {
            val plain = "default-protected".encodeToByteArray()
            val blob = e.encrypt(master, plain, hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))

            val other = uniqueAlias()
            e.deleteKey(other)
            assertTrue(dekPresent(storage), "deleting an unrelated key must not remove the shared DEK")

            val fresh = engine(storage)
            assertContentEquals(plain, fresh.decrypt(master, blob), "DEFAULT value must survive an unrelated delete")
        } finally {
            e.deleteKey(master)
        }
    }
}
