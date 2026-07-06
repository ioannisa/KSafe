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

/**
 * Device tests for the Android software-DEK fast path in [AndroidKeystoreEncryption].
 *
 * These exercise the engine directly (a real AndroidKeyStore is required, so they can't
 * run on the JVM). The wrapped DEK lives as a reserved entry ([DataStoreDekStore.DEK_KEY])
 * in the safe's own DataStore — never in SharedPreferences — so each test backs the engine
 * with its own temporary DataStore (one relaxed master KEK ⇒ one DEK per store). They assert:
 *  - relaxed DEFAULT entries are encrypted with the userspace DEK (self-describing header)
 *    and persist a wrapped DEK in the DataStore,
 *  - legacy TEE ciphertext (produced with the DEK path disabled) stays readable after the
 *    "upgrade" — the critical no-data-loss guarantee,
 *  - the strict `requireUnlockedDevice` master and `hardwareIsolated` entries keep the
 *    per-call TEE path (no DEK, no header, no DEK entry),
 *  - deleteKey / a missing DEK behave correctly for orphan reclamation, and
 *  - deleting an unrelated key never wipes the shared per-safe DEK.
 *
 * KNOWN FLAKE (device-side, not a product bug): the key-creation/encrypt calls below can
 * intermittently throw a TRANSIENT AndroidKeyStore error (keystore2 throttling under the burst of
 * key ops the full 181-test suite fires on a busy device) — surfacing as a failure AT the
 * `encrypt(...)` line, not at a DEK assertion. It reproduces only under the full suite, never in
 * isolation (each of these tests, and this whole class, passes reliably run alone), and is
 * independent of the strict/DEK logic: the `requireUnlockedDevice`/`hardwareIsolated` paths
 * provably never take the DEK branch (see [AndroidKeystoreEncryption.encrypt]'s
 * `!resolvedRequireUnlocked` guard), so a strict write can never persist a DEK. If one of these
 * fails intermittently, re-run in isolation before suspecting a regression.
 */
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

    /**
     * THE critical test: ciphertext written before the DEK fast path existed (legacy TEE,
     * no header) must remain decryptable afterwards, and new DEK writes must coexist with it.
     */
    @Test
    fun crossVersion_legacyTeeBlob_staysReadable_andNewDekBlobCoexists() {
        val storage = newStorage()
        val alias = uniqueAlias()
        val legacy = engine(storage, useSoftwareDek = false) // pre-upgrade behavior
        val upgraded = engine(storage, useSoftwareDek = true) // post-upgrade behavior (separate caches)
        try {
            val oldPlain = "legacy-tee-value".encodeToByteArray()
            val legacyBlob = legacy.encrypt(alias, oldPlain, hardwareIsolated = false, requireUnlockedDevice = false)
            assertFalse(legacyBlob.startsWithMagic(), "legacy TEE blob must NOT carry the DEK header")

            // Upgraded engine reads the legacy blob via the TEE fallback path.
            assertContentEquals(oldPlain, upgraded.decrypt(alias, legacyBlob), "legacy data must survive the upgrade")

            // A new write under the same alias uses the DEK and coexists with the old blob.
            val newPlain = "fresh-dek-value".encodeToByteArray()
            val dekBlob = upgraded.encrypt(alias, newPlain, hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekBlob.startsWithMagic(), "post-upgrade write should use the DEK header")
            assertContentEquals(newPlain, upgraded.decrypt(alias, dekBlob))
            // Old blob still readable after the DEK was introduced.
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
            // requireUnlockedDevice = true → strict TEE path, never the DEK branch (see class KDoc:
            // an intermittent throw here under full-suite load is a transient keystore flake).
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

        // deleteKey removes the master KEK. The persisted DEK may linger (its storage key is
        // fixed per safe), but without its KEK it can no longer be unwrapped.
        e.deleteKey(alias)

        // A fresh engine (cold caches) decrypting the old DEK blob must fail definitively:
        // it reads the still-present wrapped DEK from storage, then can't unwrap it (KEK gone).
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
            val fresh = engine(storage) // cold dekCache so it must read storage (now empty)
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

    /**
     * Self-heal: a persisted wrapped DEK that no longer unwraps (corrupt blob / KEK mismatch)
     * must not fail writes forever — the next encrypt regenerates a fresh DEK + KEK. (Old DEK
     * ciphertext is unrecoverable either way, exactly like a permanently-invalidated KEK.)
     */
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

            // A cold engine reads the corrupt DEK from storage; the next encrypt must recover
            // (regenerate) rather than throw, and the new value must round-trip.
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

    /**
     * Concurrent regeneration must be atomic and must not discard a sibling's
     * freshly-minted DEK. Two+ writers that all read the SAME corrupt wrapped
     * DEK each route through regenerateDek concurrently; a discard there would
     * wipe the DEK (and KEK) a sibling had already encrypted a value under,
     * silently losing that acknowledged write. Exactly one DEK must survive and
     * EVERY concurrently-written blob must still decrypt under it.
     */
    @Test
    fun concurrentRegenerate_doesNotDiscardAnotherWritersFreshDek() {
        val storage = newStorage()
        val master = uniqueAlias()
        val seed = engine(storage)
        try {
            // Establish a DEK, then corrupt the persisted wrapped DEK so every cold-engine
            // unwrap fails and routes through regenerateDek.
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

            // Cold engine (empty dekCache) → all N concurrent encrypts hit the corrupt DEK
            // and regenerate concurrently.
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

            // Decisive: every concurrently-regenerated write round-trips — a writer
            // whose fresh DEK was discarded by a sibling regenerate would fail to decrypt.
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

    /**
     * A corrupt wrapped DEK must self-heal by minting a fresh DEK under the
     * SAME (healthy) KEK — it must NOT delete the KEK, or pre-upgrade legacy TEE ciphertext
     * still encrypted directly under that KEK would be permanently destroyed.
     */
    @Test
    fun corruptDek_selfHeals_withoutDestroyingLegacyTeeCiphertextUnderSameKek() {
        val storage = newStorage()
        val master = uniqueAlias()
        try {
            // Pre-upgrade: a legacy TEE blob encrypted DIRECTLY under the master KEK (DEK off).
            val legacy = engine(storage, useSoftwareDek = false)
            val legacyBlob = legacy.encrypt(master, "legacy-value".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertFalse(legacyBlob.startsWithMagic(), "precondition: legacy TEE blob has no DEK header")

            // Upgrade: a DEK write wraps a fresh DEK under that same KEK.
            val dekEngine = engine(storage, useSoftwareDek = true)
            dekEngine.encrypt(master, "dek-value".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))

            // The wrapped DEK becomes corrupt (fails GCM auth) — but the KEK is fine.
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

            // A cold engine self-heals on the next encrypt (mints a new DEK under the SAME KEK).
            val fresh = engine(storage, useSoftwareDek = true)
            val healed = fresh.encrypt(master, "after".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertContentEquals("after".encodeToByteArray(), fresh.decrypt(master, healed), "regenerated DEK must round-trip")

            // The decisive check: the legacy TEE ciphertext under the KEK must STILL decrypt —
            // a self-heal that deleted the KEK would make this throw "No encryption key found".
            assertContentEquals(
                "legacy-value".encodeToByteArray(),
                fresh.decrypt(master, legacyBlob),
                "legacy TEE ciphertext under the same KEK must survive a corrupt-DEK self-heal",
            )
        } finally {
            engine(storage).deleteKey(master)
        }
    }

    /**
     * A wrapped DEK present while its KEK is ABSENT (Auto Backup restored the
     * DataStore to a device with an empty Keystore, and an encrypted write beat the prewarm)
     * must self-heal on the next encrypt, not brick every write with "No encryption key found".
     */
    @Test
    fun wrappedDekPresent_butKekAbsent_selfHealsOnEncrypt() {
        val storage = newStorage()
        val master = uniqueAlias()
        val e = engine(storage)
        try {
            e.encrypt(master, "v1".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))

            // deleteKey removes the KEK from the Keystore but LEAVES the persisted wrapped DEK
            // (its storage key is fixed per safe) — exactly the restored-DataStore + empty-
            // Keystore state.
            e.deleteKey(master)
            assertTrue(dekPresent(storage), "precondition: wrapped DEK still present after KEK deletion")

            val fresh = engine(storage) // cold caches
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

    /**
     * A MALFORMED wrapped-DEK entry (invalid Base64 / blob shorter than the
     * GCM IV) must self-heal like the corrupt-but-well-formed case — not bypass the recovery
     * and brick encrypted writes forever.
     */
    @Test
    fun malformedWrappedDek_selfHealsOnEncrypt() {
        val storage = newStorage()
        val master = uniqueAlias()
        val e = engine(storage)
        try {
            e.encrypt(master, "v1".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))

            // Invalid Base64 → load() throws IllegalArgumentException (not AEADBadTagException);
            // the self-heal must catch this shape too, or every encrypted write bricks.
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

    /**
     * Lazy DEK: prewarm warms only the wrapping KEK and must NOT persist a DEK, so an
     * unencrypted-only safe never writes one. The DEK appears on the first real encrypt.
     */
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

    /**
     * Guards the fixed-key delete semantics: the per-safe DEK has ONE storage key, so deleting
     * an unrelated (per-entry / HARDWARE_ISOLATED) key must never remove it — otherwise every
     * relaxed DEFAULT value in the safe would be bricked.
     */
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
            e.deleteKey(other) // an unrelated key — must not touch the shared DEK
            assertTrue(dekPresent(storage), "deleting an unrelated key must not remove the shared DEK")

            // The DEFAULT value still decrypts — proven from storage via a cold engine.
            val fresh = engine(storage)
            assertContentEquals(plain, fresh.decrypt(master, blob), "DEFAULT value must survive an unrelated delete")
        } finally {
            e.deleteKey(master)
        }
    }
}
