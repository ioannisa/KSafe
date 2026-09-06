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
 * Locks in the generation-aware wrapped-DEK store: each master alias (base and rotation generations
 * like `<base>.g2`) wraps its own persisted DEK, so a first rotate-encrypt can no longer destroy the
 * one shared slot and brick every not-yet-rotated DEFAULT entry after a restart. The base alias also
 * keeps the exact historical record key, and deleteKey reclaims exactly one generation's record.
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
        // Zero-migration invariant: the base alias maps to the exact pre-3.0.0 record key.
        assertEquals(DataStoreDekStore.DEK_KEY, DataStoreDekStore.recordKeyFor(base, base))
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

        // A gen-1 DEFAULT entry under the base master, i.e. the software-DEK path.
        val gen1Plain = "gen1-acknowledged-value".encodeToByteArray()
        val gen1Ct = engine.encrypt(base, gen1Plain, hardwareIsolated = false, requireUnlockedDevice = false)
        assertTrue(storage.snapshot().containsKey(DataStoreDekStore.DEK_KEY), "gen-1 DEK record persisted")

        // This first encrypt under the gen-2 alias once loaded the shared slot, failed to unwrap
        // with the g2 KEK, and let the recovery path delete the only copy of the gen-1 DEK.
        val g2 = "$base.g2"
        val gen2Plain = "gen2-rotated-value".encodeToByteArray()
        val gen2Ct = engine.encrypt(g2, gen2Plain, hardwareIsolated = false, requireUnlockedDevice = false)

        val snapshot = storage.snapshot()
        assertTrue(snapshot.containsKey(DataStoreDekStore.DEK_KEY), "gen-1 DEK record must SURVIVE the g2 mint")
        assertTrue(
            snapshot.containsKey(DataStoreDekStore.recordKeyFor(base, g2)),
            "gen-2 got its own DEK record",
        )

        // A cold engine over the same storage is the post-restart state a crash mid-rotation
        // leaves behind: dekCache empty, records on disk. Both generations must decrypt.
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
        // Alias isolation: a g5 read must not fall back to the base record, it must fail with the
        // canonical missing-key error and leave healing decisions to the caller.
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

        // The rotation sweep's reclamation: the superseded generation loses its DEK record and KEK.
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

        // ...and the next encrypt re-mints and re-persists, so no key material stays RAM-only.
        val ct = engine.encrypt(base, "y".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
        assertTrue(storage.snapshot().containsKey(DataStoreDekStore.DEK_KEY), "re-mint must persist a fresh record")
        val cold = AndroidKeystoreEncryption(
            config = KSafeConfig(),
            dekStore = DataStoreDekStore(storage, baseAlias = base),
        )
        assertContentEquals("y".encodeToByteArray(), cold.decrypt(base, ct, requireUnlockedDevice = false))
    }
}
