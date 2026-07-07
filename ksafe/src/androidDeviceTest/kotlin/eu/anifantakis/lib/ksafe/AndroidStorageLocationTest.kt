package eu.anifantakis.lib.ksafe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Locks in: baseDir routes the DataStore into a caller-supplied path, and the dataStoreCache keyed by resolved path isolates same-fileName / different-baseDir instances. */
@RunWith(AndroidJUnit4::class)
class AndroidStorageLocationTest {

    private fun uniqueName(prefix: String): String {
        // KSafe filename regex: [a-z][a-z0-9_]*
        val salt = UUID.randomUUID().toString().lowercase().filter { it in 'a'..'z' }.take(8)
        return "${prefix.lowercase()}_$salt"
    }

    /** `baseDir = customDir` routes the DataStore file into the provided directory. */
    @Test
    fun baseDir_storesFileInProvidedDirectory() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val name = uniqueName("basedir")
        val tmpDir = File(context.cacheDir, "ksafeTest_$name").apply { mkdirs() }

        try {
            val safe = KSafe(context = context, fileName = name, baseDir = tmpDir)
            safe.put("hello", "world")

            val expected = File(tmpDir, "eu_anifantakis_ksafe_datastore_$name.preferences_pb")
            assertTrue(expected.exists(), "Expected $expected to exist")

            // Roundtrip confirms the DataStore is backed by that file.
            assertEquals("world", safe.get("hello", "fallback"))
        } finally {
            tmpDir.deleteRecursively()
        }
    }

    /** Same fileName + different baseDir must yield isolated DataStores: the cache key is the absolute path, so they don't collapse onto one store and trip "multiple active instances". */
    @Test
    fun baseDir_dataStoreCacheKey_isolatesByPath() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val sharedName = uniqueName("shared")
        val dirA = File(context.cacheDir, "ksafeTest_${sharedName}_a").apply { mkdirs() }
        val dirB = File(context.cacheDir, "ksafeTest_${sharedName}_b").apply { mkdirs() }

        try {
            val safeA = KSafe(context = context, fileName = sharedName, baseDir = dirA)
            val safeB = KSafe(context = context, fileName = sharedName, baseDir = dirB)

            safeA.put("k", "value_a", KSafeWriteMode.Plain)
            safeB.put("k", "value_b", KSafeWriteMode.Plain)

            val fileA = File(dirA, "eu_anifantakis_ksafe_datastore_$sharedName.preferences_pb")
            val fileB = File(dirB, "eu_anifantakis_ksafe_datastore_$sharedName.preferences_pb")
            assertTrue(fileA.exists(), "File should exist in dirA")
            assertTrue(fileB.exists(), "File should exist in dirB")

            // Reaching here without a "multiple active instances" crash already proves path
            // isolation; the values confirm each instance has its own store.
            assertEquals("value_a", safeA.get("k", "fallback"))
            assertEquals("value_b", safeB.get("k", "fallback"))
        } finally {
            dirA.deleteRecursively()
            dirB.deleteRecursively()
        }
    }
}
