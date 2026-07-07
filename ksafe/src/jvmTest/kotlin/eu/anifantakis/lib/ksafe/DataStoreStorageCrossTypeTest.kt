package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.runTest
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Locks in: switching a DataStore key plain↔encrypted (same raw name, different [StoredValue] type) leaves no stale entry of the old type on disk, and delete removes every same-name entry.
 */
class DataStoreStorageCrossTypeTest {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tmpDir: File = Files.createTempDirectory("ksafe-dss-test").toFile()

    private fun newStorage(): DataStoreStorage {
        val file = File(tmpDir, "dss_${System.nanoTime()}.preferences_pb")
        val ds: DataStore<Preferences> = PreferenceDataStoreFactory.create(scope = scope) { file }
        return DataStoreStorage(ds)
    }

    @AfterTest
    fun tearDown() {
        scope.cancel()
        tmpDir.deleteRecursively()
    }

    @Test
    fun switchingPlainToEncryptedLeavesNoStalePlaintext() = runTest {
        val storage = newStorage()
        val rawKey = "__ksafe_value_token"

        storage.applyBatch(listOf(StorageOp.Put(rawKey, StoredValue.IntVal(42))))
        assertEquals(StoredValue.IntVal(42), storage.snapshot()[rawKey])

        // Re-write as encrypted Text under the SAME raw key.
        storage.applyBatch(listOf(StorageOp.Put(rawKey, StoredValue.Text("ciphertext-base64"))))

        val snap = storage.snapshot()
        assertEquals(
            StoredValue.Text("ciphertext-base64"), snap[rawKey],
            "the encrypted Text must fully replace the stale plain Int",
        )
        assertTrue(
            snap[rawKey] !is StoredValue.IntVal,
            "plaintext Int must NOT linger on disk after switching the key to encrypted",
        )
    }

    @Test
    fun switchingEncryptedToPlainReplacesCleanly() = runTest {
        val storage = newStorage()
        val rawKey = "__ksafe_value_count"

        storage.applyBatch(listOf(StorageOp.Put(rawKey, StoredValue.Text("ciphertext"))))
        storage.applyBatch(listOf(StorageOp.Put(rawKey, StoredValue.IntVal(7))))

        assertEquals(
            StoredValue.IntVal(7), storage.snapshot()[rawKey],
            "the plain Int must fully replace the stale ciphertext Text",
        )
    }

    @Test
    fun deleteRemovesTheEntryEvenAfterTypeChurn() = runTest {
        val storage = newStorage()
        val rawKey = "__ksafe_value_k"

        storage.applyBatch(listOf(StorageOp.Put(rawKey, StoredValue.IntVal(1))))
        storage.applyBatch(listOf(StorageOp.Put(rawKey, StoredValue.Text("ct"))))
        storage.applyBatch(listOf(StorageOp.Delete(rawKey)))

        assertNull(
            storage.snapshot()[rawKey],
            "delete must remove the entry completely, regardless of prior type churn",
        )
    }
}
