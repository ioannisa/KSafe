package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals

/** Locks in: recreating a safe on the same file awaits the previous owner's DataStore teardown, so rapid close→recreate never trips "multiple DataStores active for the same file". */
@RunWith(AndroidJUnit4::class)
class AndroidDataStoreLifecycleTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun closeThenRecreate_sameFile_survives_andDataPersists() = runBlocking {
        val fileName = "lifecycle_${System.nanoTime()}"
        try {
            // Each iteration recreates a safe on the SAME file, writes, reads, and closes;
            // a regressed await would throw "multiple DataStores active for the same file".
            repeat(30) { i ->
                val ks = KSafe(context, fileName = fileName)
                ks.put("counter", i)
                assertEquals(i, ks.get("counter", -1), "value must round-trip within the instance")
                ks.close()
            }
            // The last write must survive a final reopen (its DEK persisted across every recreate).
            val reopened = KSafe(context, fileName = fileName)
            assertEquals(29, reopened.get("counter", -1), "data must persist across close→recreate")
            reopened.close()
        } finally {
            val cleanup = KSafe(context, fileName = fileName)
            cleanup.clearAll()
            cleanup.close()
        }
    }
}
