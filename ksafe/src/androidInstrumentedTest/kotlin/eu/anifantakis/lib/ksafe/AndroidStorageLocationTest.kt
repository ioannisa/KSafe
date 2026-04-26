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

/**
 * Android-specific instrumented tests for the new 2.0 storage-location feature:
 *
 *  1. The `baseDir` parameter routes the DataStore into a caller-supplied path.
 *  2. The Android `dataStoreCache` is now keyed by the resolved file path
 *     (not by `fileName ?: "default"`), so two `KSafe` instances with the same
 *     `fileName` but different `baseDir`s get isolated DataStores instead of
 *     conflicting on DataStore's "multiple active instances" error.
 */
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

            // Roundtrip — confirms the DataStore is actually backed by that file.
            assertEquals("world", safe.get("hello", "fallback"))
        } finally {
            tmpDir.deleteRecursively()
        }
    }

    /**
     * Two KSafe instances with the **same fileName** but **different baseDir**s
     * must get isolated DataStores. Pre-2.0 the `dataStoreCache` was keyed by
     * `fileName ?: "default"` and would have collapsed them onto one DataStore
     * (DataStore would then throw "multiple active instances"). The 2.0 cache
     * key is `datastoreFile.absolutePath` so the two are distinguished.
     */
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

            // Reads should not bleed across instances — each KSafe has its own
            // DataStore + KSafeCore + hot cache, and the writes went to different
            // files. If the cache key still collapsed by fileName they would have
            // crashed at construction with DataStore's "multiple active instances"
            // error; reaching this assertion means the cache key correctly
            // isolates by path.
            assertEquals("value_a", safeA.get("k", "fallback"))
            assertEquals("value_b", safeB.get("k", "fallback"))
        } finally {
            dirA.deleteRecursively()
            dirB.deleteRecursively()
        }
    }
}
