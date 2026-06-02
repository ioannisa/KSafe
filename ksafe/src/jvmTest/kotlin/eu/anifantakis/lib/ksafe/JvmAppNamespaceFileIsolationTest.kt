package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Regression tests for #6: on JVM, an explicitly-set `appNamespace` must isolate
 * the DATA FILE (per-namespace subdirectory), not just the OS-vault keys — so two
 * apps sharing a `fileName` on one OS account can't clobber a single file, and one
 * app's `clearAll()` can't wipe another's data. Apps that don't set `appNamespace`
 * keep the historical un-namespaced path. Existing un-namespaced data is migrated
 * (copied) into the subdir on first run with a namespace.
 *
 * Uses a temp `baseDir` + `FakeEncryption` so nothing touches the real
 * `~/.eu_anifantakis_ksafe` or the OS keychain; the tests exercise the FILE-path
 * isolation, which is the fix.
 */
class JvmAppNamespaceFileIsolationTest {

    private val tmp: File = Files.createTempDirectory("ksafe-appns").toFile()

    @AfterTest
    fun tearDown() {
        tmp.deleteRecursively()
    }

    private val pbName = "eu_anifantakis_ksafe_datastore_data.preferences_pb"

    @Test
    fun differentNamespacesDoNotClobberOrCrossWipe() = runTest {
        // App A writes "data/k" under namespace "appa", commits, closes.
        val a = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "appa"), baseDir = tmp, testEngine = FakeEncryption())
        a.put("k", "fromA")
        delay(300); a.close(); delay(100)

        // App B — SAME fileName, DIFFERENT namespace — writes its own value, then clearAll().
        val b = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "appb"), baseDir = tmp, testEngine = FakeEncryption())
        b.put("k", "fromB")
        delay(300)
        b.clearAll()
        delay(200); b.close()

        // Files live in per-namespace subdirs — proof the paths are isolated.
        assertTrue(File(tmp, "appa/$pbName").exists(), "appa's file must be in its own subdir")

        // Reopen A cold: its data survived B's write AND B's clearAll (separate file).
        val aReopened = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "appa"), baseDir = tmp, lazyLoad = true, testEngine = FakeEncryption())
        assertEquals(
            "fromA", aReopened.get("k", "?"),
            "appA's data must be isolated from appB's write and clearAll()",
        )
        aReopened.close()
    }

    @Test
    fun noAppNamespaceKeepsHistoricalUnNamespacedPath() = runTest {
        val ksafe = KSafe(fileName = "data", baseDir = tmp, testEngine = FakeEncryption())
        ksafe.put("x", "v")
        delay(300); ksafe.close()

        assertTrue(
            File(tmp, pbName).exists(),
            "an instance without appNamespace must use the historical un-namespaced path (no subdir)",
        )
    }

    @Test
    fun existingUnNamespacedDataMigratesIntoTheNamespaceSubdir() = runTest {
        // Seed at the OLD un-namespaced path (no appNamespace).
        val old = KSafe(fileName = "data", baseDir = tmp, testEngine = FakeEncryption())
        old.put("k", "seeded")
        delay(300); old.close(); delay(200)
        assertTrue(File(tmp, pbName).exists(), "precondition: seeded at the un-namespaced path")

        // Reopen WITH a namespace → the one-time COPY migration carries it forward.
        val migrated = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "appx"), baseDir = tmp, lazyLoad = true, testEngine = FakeEncryption())
        assertEquals(
            "seeded", migrated.get("k", "?"),
            "existing un-namespaced data must be migrated into the namespace subdir",
        )
        assertTrue(File(tmp, "appx/$pbName").exists(), "migrated copy must exist in the subdir")
        // COPY, not move: the original is left in place (so a second app can't lose it).
        assertTrue(File(tmp, pbName).exists(), "migration must COPY, leaving the original")
        migrated.close()
    }
}
