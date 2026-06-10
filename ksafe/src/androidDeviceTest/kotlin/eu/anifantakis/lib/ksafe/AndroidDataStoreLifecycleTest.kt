package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertEquals

/**
 * Regression test for the Android DataStore close→recreate lifecycle (see `KSafe.android.kt`).
 *
 * Closing a safe cancels its DataStore scope; DataStore releases the underlying file only
 * once that scope's `Job` completes. Recreating a safe on the **same file** must therefore
 * await the previous owner's teardown, or it trips DataStore's
 * `IllegalStateException: There are multiple DataStores active for the same file`.
 *
 * This intermittently failed the device suite before the factory learned to await the prior
 * scope; the loop here reproduces the create-after-close pressure deterministically so a
 * future regression of that await is caught.
 */
@RunWith(AndroidJUnit4::class)
class AndroidDataStoreLifecycleTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun closeThenRecreate_sameFile_survives_andDataPersists() = runBlocking {
        val fileName = "lifecycle_${System.nanoTime()}"
        try {
            // Each iteration: a fresh safe on the SAME file → encrypted write (DEK + value
            // DataStore activity) → read back → close (cancels the store's scope). A
            // regressed await would throw "multiple DataStores active for the same file"
            // on one of the recreates.
            repeat(30) { i ->
                val ks = KSafe(context, fileName = fileName)
                ks.put("counter", i) // encrypted by default
                assertEquals(i, ks.get("counter", -1), "value must round-trip within the instance")
                ks.close()
            }
            // The value written by the last living instance must survive a final reopen
            // (encrypted with a DEK that persisted across every recreate).
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
