package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.DataStoreDekStore
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
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
 * Locks in the generation-aware wrapped-DEK store (3.0.0): each master alias (base and rotation
 * generations like `<base>.g2`) wraps its OWN persisted DEK, so the first rotate-encrypt under a
 * new generation can no longer destroy the single shared slot and brick every not-yet-rotated
 * DEFAULT entry after a restart. Also: the base alias keeps the exact historical record key
 * (zero-migration invariant), and deleteKey reclaims exactly one generation's record.
 */
@RunWith(AndroidJUnit4::class)
class AndroidDekRotationTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private val scopes = mutableListOf<CoroutineScope>()
    private val files = mutableListOf<File>()

    @After
    fun tearDown() {
        scopes.forEach { runCatching { it.cancel() } }
        files.forEach { runCatching { it.delete() } }
    }

    private var counter = 0
    private fun uniqueAlias(): String =
        "eu.anifantakis.ksafe.dekrot${System.currentTimeMillis()}_${counter++}"

    private fun newEngineWithStorage(baseAlias: String): Pair<AndroidKeystoreEncryption, DataStoreStorage> {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO).also { scopes += it }
        val file = File(context.filesDir, "dekrot_${System.nanoTime()}.preferences_pb").also { files += it }
        val dataStore = PreferenceDataStoreFactory.create(scope = scope, produceFile = { file })
        val storage = DataStoreStorage(dataStore)
        val engine = AndroidKeystoreEncryption(
            config = KSafeConfig(),
            dekStore = DataStoreDekStore(storage, baseAlias = baseAlias),
        )
        return engine to storage
    }

    @Test
    fun recordKeys_baseKeepsHistoricalSlot_generationsGetTheirOwn() {
        val base = "eu.anifantakis.ksafe.__ksafe_master__"
        // Zero-migration invariant: the base alias maps to the EXACT pre-3.0.0 record key.
        assertEquals(DataStoreDekStore.DEK_KEY, DataStoreDekStore.recordKeyFor(base, base))
        // Rotated generations get distinct records, still inside the reserved namespace.
        val g2 = DataStoreDekStore.recordKeyFor(base, "$base.g2")
        val g3 = DataStoreDekStore.recordKeyFor(base, "$base.g3")
        assertTrue(g2.startsWith("__ksafe_"), "generation records stay internal")
        assertFalse(g2 == DataStoreDekStore.DEK_KEY, "a generation must not share the base slot")
        assertFalse(g2 == g3, "each generation gets its own record")
    }

    @Test
    fun firstEncryptUnderNewGeneration_noLongerDestroysTheGen1Dek() = runBlocking {
        val base = uniqueAlias()
        val (engine, storage) = newEngineWithStorage(base)

        // Gen-1 world: a DEFAULT entry encrypted under the base master (software-DEK path).
        val gen1Plain = "gen1-acknowledged-value".encodeToByteArray()
        val gen1Ct = engine.encrypt(base, gen1Plain, hardwareIsolated = false, requireUnlockedDevice = false)
        assertTrue(storage.snapshot().containsKey(DataStoreDekStore.DEK_KEY), "gen-1 DEK record persisted")

        // Rotation begins: first encrypt under the gen-2 master alias. Pre-fix this loaded the
        // shared slot, failed to unwrap with the g2 KEK, and the recovery path DELETED the only
        // persisted copy of the gen-1 DEK.
        val g2 = "$base.g2"
        val gen2Plain = "gen2-rotated-value".encodeToByteArray()
        val gen2Ct = engine.encrypt(g2, gen2Plain, hardwareIsolated = false, requireUnlockedDevice = false)

        val snapshot = storage.snapshot()
        assertTrue(snapshot.containsKey(DataStoreDekStore.DEK_KEY), "gen-1 DEK record must SURVIVE the g2 mint")
        assertTrue(
            snapshot.containsKey(DataStoreDekStore.recordKeyFor(base, g2)),
            "gen-2 got its own DEK record",
        )

        // Crash-mid-rotation contract: BOTH generations decrypt from a COLD engine (fresh caches
        // over the SAME storage) — exactly the post-restart state: dekCache empty, records on disk.
        val cold = AndroidKeystoreEncryption(
            config = KSafeConfig(),
            dekStore = DataStoreDekStore(storage, baseAlias = base),
        )
        assertContentEquals(gen1Plain, cold.decrypt(base, gen1Ct, requireUnlockedDevice = false))
        assertContentEquals(gen2Plain, cold.decrypt(g2, gen2Ct, requireUnlockedDevice = false))
    }

    @Test
    fun decryptUnderWrongGenerationAlias_failsCleanly_neverAdoptsAnotherGenerationsDek() = runBlocking {
        val base = uniqueAlias()
        val (engine, _) = newEngineWithStorage(base)
        val ct = engine.encrypt(base, "v".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
        // A g5 read must NOT silently fall back to the base record (alias isolation): it fails
        // with the canonical missing-key error, leaving healing decisions to the caller.
        assertFails { engine.decrypt("$base.g5", ct, requireUnlockedDevice = false) }
        Unit
    }

    @Test
    fun deleteKey_reclaimsExactlyThatGenerationsRecord() = runBlocking {
        val base = uniqueAlias()
        val (engine, storage) = newEngineWithStorage(base)
        val gen1Ct = engine.encrypt(base, "one".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
        val g2 = "$base.g2"
        val gen2Ct = engine.encrypt(g2, "two".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)

        // The rotation sweep's reclamation: deleting the superseded base generation removes
        // its DEK record + KEK, leaving gen-2 fully intact.
        engine.deleteKey(base)
        val snapshot = storage.snapshot()
        assertFalse(snapshot.containsKey(DataStoreDekStore.DEK_KEY), "swept generation's DEK record reclaimed")
        assertTrue(snapshot.containsKey(DataStoreDekStore.recordKeyFor(base, g2)), "live generation untouched")
        assertContentEquals("two".encodeToByteArray(), engine.decrypt(g2, gen2Ct, requireUnlockedDevice = false))
        assertFails { engine.decrypt(base, gen1Ct, requireUnlockedDevice = false) }
        Unit
    }

    @Test
    fun onStoreCleared_dropsCachedDeks_nextEncryptRemintsAndPersists() = runBlocking {
        val base = uniqueAlias()
        val (engine, storage) = newEngineWithStorage(base)
        engine.encrypt(base, "x".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
        assertTrue(engine.isDekCachedForTest(base))

        // Simulate performClearAll: the store wipe removes the record behind the cache's back...
        runBlocking { storage.clear() }
        engine.onStoreCleared()
        assertFalse(engine.isDekCachedForTest(base), "wiped store must purge the DEK cache")

        // ...and the next encrypt re-mints AND re-persists (no RAM-only key material).
        val ct = engine.encrypt(base, "y".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
        assertTrue(storage.snapshot().containsKey(DataStoreDekStore.DEK_KEY), "re-mint must persist a fresh record")
        val cold = AndroidKeystoreEncryption(
            config = KSafeConfig(),
            dekStore = DataStoreDekStore(storage, baseAlias = base),
        )
        assertContentEquals("y".encodeToByteArray(), cold.decrypt(base, ct, requireUnlockedDevice = false))
    }
}
