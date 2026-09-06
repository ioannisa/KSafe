package eu.anifantakis.lib.ksafe

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.emptyPreferences
import eu.anifantakis.lib.ksafe.internal.DataStoreStorage
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.keyvault.DataStorePrefStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Windows fails DataStore's tmp→target rename with a sharing violation while another program
 * (antivirus, indexer, backup) holds either file open. Locks in: the store rewrite retries that
 * transient failure instead of failing the caller's write, and fails fast on anything else.
 */
class JvmTransientRenameRetryTest {

    private val renameMessage =
        "Unable to rename /tmp/store.preferences_pb.tmp to /tmp/store.preferences_pb. " +
            "This likely means that there are multiple instances of DataStore for this file. " +
            "Ensure that you are only creating a single instance of datastore for this file."

    /** In-memory [DataStore] that fails its first [failures] writes the way Windows does. */
    private class FlakyRenameDataStore(
        private val failures: Int,
        private val message: String,
    ) : DataStore<Preferences> {
        private val state = MutableStateFlow(emptyPreferences())
        var attempts: Int = 0
            private set

        override val data: Flow<Preferences> get() = state

        override suspend fun updateData(transform: suspend (t: Preferences) -> Preferences): Preferences {
            attempts++
            if (attempts <= failures) throw IOException(message)
            return transform(state.value).also { state.value = it }
        }
    }

    private suspend fun capturingStdout(block: suspend () -> Unit): String {
        val buffer = ByteArrayOutputStream()
        val original = System.out
        System.setOut(PrintStream(buffer, true))
        try {
            block()
        } finally {
            System.setOut(original)
        }
        return buffer.toString()
    }

    @Test
    fun putSurvivesATransientRenameFailure() = runTest {
        val ds = FlakyRenameDataStore(failures = 3, message = renameMessage)
        val storage = DataStoreStorage(ds)

        val logged = capturingStdout {
            storage.applyBatch(listOf(StorageOp.Put("__ksafe_value_token", StoredValue.Text("kept"))))
        }

        assertEquals(4, ds.attempts, "the write must be retried until the rename lands")
        assertEquals(
            StoredValue.Text("kept"), storage.snapshot()["__ksafe_value_token"],
            "the retried write must persist the value",
        )
        val warnings = logged.lines().count { it.contains("KSafe:") }
        assertEquals(1, warnings, "exactly one warning must report the retried rewrite, got: $logged")
        assertTrue(logged.contains("rename"), "the warning must name the rename failure: $logged")
    }

    @Test
    fun clearSurvivesATransientRenameFailure() = runTest {
        val ds = FlakyRenameDataStore(failures = 2, message = renameMessage)
        val storage = DataStoreStorage(ds)

        capturingStdout { storage.clear() }

        assertEquals(3, ds.attempts, "clear() must retry the same transient failure")
    }

    @Test
    fun aRenameThatNeverLandsStillFailsTheWrite() = runTest {
        val ds = FlakyRenameDataStore(failures = Int.MAX_VALUE, message = renameMessage)
        val storage = DataStoreStorage(ds)

        val failure = assertFailsWith<IOException> {
            storage.applyBatch(listOf(StorageOp.Put("__ksafe_value_token", StoredValue.Text("lost"))))
        }

        assertTrue(failure.message!!.startsWith("Unable to rename"), "the original failure must propagate")
        assertEquals(6, ds.attempts, "the retry budget is one attempt plus five retries")
    }

    @Test
    fun keyVaultWritesSurviveATransientRenameFailure() {
        val ds = FlakyRenameDataStore(failures = 2, message = renameMessage)
        val store = DataStorePrefStore(ds, "ksafe_key_")

        runBlocking { capturingStdout { store.putString("alias", "wrapped") } }

        assertEquals(3, ds.attempts, "the key record write must retry the same transient failure")
        assertEquals("wrapped", store.getString("alias"))
    }

    @Test
    fun anUnrelatedIoFailureIsNotRetried() = runTest {
        val ds = FlakyRenameDataStore(failures = Int.MAX_VALUE, message = "No space left on device")
        val storage = DataStoreStorage(ds)

        val failure = assertFailsWith<IOException> {
            storage.applyBatch(listOf(StorageOp.Put("__ksafe_value_token", StoredValue.Text("x"))))
        }

        assertEquals("No space left on device", failure.message)
        assertEquals(1, ds.attempts, "only DataStore's rename failure is transient; everything else fails fast")
    }
}
