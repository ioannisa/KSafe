package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.DataStoreDekStore
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
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
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Locks in: prewarmDekReadIfPresent warms an already-persisted DEK into the in-process cache in the background (so the first encrypted read avoids a blocking storage round-trip / UI-thread ANR), and stays strictly read-only so an unencrypted-only safe never persists a DEK. */
@RunWith(AndroidJUnit4::class)
class AndroidDekPrewarmTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private val scopes = mutableListOf<CoroutineScope>()
    private val files = mutableListOf<File>()

    @After
    fun tearDown() {
        scopes.forEach { runCatching { it.cancel() } }
        files.forEach { runCatching { it.delete() } }
    }

    private var counter = 0
    private fun uniqueAlias(): String { counter++; return "ksafe_prewarm_${System.nanoTime()}_$counter" }

    private fun newStorage(): DataStoreStorage {
        counter++
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob()); scopes += scope
        val file = File(context.cacheDir, "prewarm_${System.nanoTime()}_$counter.preferences_pb"); files += file
        return DataStoreStorage(PreferenceDataStoreFactory.create(scope = scope) { file })
    }

    private fun engine(storage: DataStoreStorage) =
        AndroidKeystoreEncryption(config = KSafeConfig(), dekStore = DataStoreDekStore(storage), useSoftwareDek = true)

    private fun dekPresent(storage: DataStoreStorage): Boolean =
        runBlocking { storage.snapshot().containsKey(DataStoreDekStore.DEK_KEY) }

    @Test
    fun prewarmDekReadIfPresent_warmsPersistedDek_soReadIsServedFromCache() {
        val storage = newStorage()
        val master = uniqueAlias()
        val e1 = engine(storage)
        try {
            val blob = e1.encrypt(master, "secret".encodeToByteArray(), hardwareIsolated = false, requireUnlockedDevice = false)
            assertTrue(dekPresent(storage))

            // A fresh cold-cache engine on the same storage warms the DEK.
            val e2 = engine(storage)
            assertFalse(e2.isDekCachedForTest(master), "precondition: the cold engine has no cached DEK")
            runBlocking { e2.prewarmDekReadIfPresent(master, requireUnlockedDevice = false) }
            assertTrue(e2.isDekCachedForTest(master), "prewarm must warm the persisted DEK into the cache")

            // Prove it's served from cache: remove the DEK from storage; a warm cache still decrypts.
            runBlocking { storage.applyBatch(listOf(StorageOp.Delete(DataStoreDekStore.DEK_KEY))) }
            assertContentEquals(
                "secret".encodeToByteArray(),
                e2.decrypt(master, blob),
                "the prewarmed DEK must serve the read from cache without a storage round-trip",
            )
        } finally {
            e1.deleteKey(master)
        }
    }

    @Test
    fun prewarmDekReadIfPresent_isNoOp_forAnUnencryptedOnlySafe() {
        val storage = newStorage()
        val master = uniqueAlias()
        val e = engine(storage)
        try {
            runBlocking { e.prewarmDekReadIfPresent(master, requireUnlockedDevice = false) }
            assertFalse(dekPresent(storage), "read-only prewarm must NOT create/persist a DEK when none exists")
        } finally {
            e.deleteKey(master)
        }
    }
}
