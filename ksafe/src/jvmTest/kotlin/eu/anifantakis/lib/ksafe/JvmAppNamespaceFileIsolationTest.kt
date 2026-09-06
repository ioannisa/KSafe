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
 * Locks in: on JVM an explicit appNamespace isolates the data file into a per-namespace subdirectory,
 * so neither a write nor a wipe from another app can reach it, while no namespace keeps the
 * historical path and existing un-namespaced data is copied forward on the first namespaced run.
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
        val a = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "appa"), baseDir = tmp, testEngine = FakeEncryption())
        a.put("k", "fromA")
        delay(300); a.close(); delay(100)

        // App B: same fileName, different namespace, and it wipes.
        val b = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "appb"), baseDir = tmp, testEngine = FakeEncryption())
        b.put("k", "fromB")
        delay(300)
        b.clearAll()
        delay(200); b.close()

        assertTrue(File(tmp, "appa/$pbName").exists(), "appa's file must be in its own subdir")

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
    fun namespaceCopyForward_preservesSourceMtimes_forTheMigrationGate() {
        // The migration gate compares the fallback JSON's mtime against the `.migrated` marker's.
        // copyTo stamps copy time, and the marker is copied last, so inside the namespace subdir
        // the gate would be deterministically off and a newer second fallback period stranded.
        val base = "eu_anifantakis_ksafe_datastore_data"
        val now = System.currentTimeMillis()
        val srcMarker = File(tmp, "$base.ksafe.json.migrated").apply { writeText("archive") }
        srcMarker.setLastModified(now - 120_000)
        val srcJson = File(tmp, "$base.ksafe.json").apply { writeText("{}") }
        srcJson.setLastModified(now - 60_000)

        val ksafe = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "appm"), baseDir = tmp, lazyLoad = true, testEngine = FakeEncryption())
        ksafe.close()

        val nsJson = File(tmp, "appm/$base.ksafe.json")
        val nsMarker = File(tmp, "appm/$base.ksafe.json.migrated")
        assertTrue(nsJson.exists() && nsMarker.exists(), "both files must be copied forward")
        assertTrue(
            nsJson.lastModified() > nsMarker.lastModified(),
            "copied files must keep their source mtimes so a newer fallback stays newer than the marker",
        )
    }

    @Test
    fun dotPrefixedNamespaceToken_resolvesToTheSameStoreAsItsCanonicalForm() = runTest {
        // ".foo" and "foo" are one identity on the data-dir side, matching the key vault's
        // normalization; split identities let one app's clearAll destroy keys the other needs.
        val a = KSafe(fileName = "data", config = KSafeConfig(appNamespace = ".foo"), baseDir = tmp, testEngine = FakeEncryption())
        a.put("k", "fromDot")
        delay(300); a.close(); delay(100)

        val b = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "foo"), baseDir = tmp, lazyLoad = true, testEngine = FakeEncryption())
        assertEquals("fromDot", b.get("k", "?"), "'.foo' and 'foo' must resolve to one store")
        b.close()
        assertTrue(File(tmp, "foo/$pbName").exists(), "the shared canonical subdir is 'foo'")
    }

    @Test
    fun legacyUnderscoredNamespaceDir_isCarriedForwardIntoTheCanonicalDir() = runTest {
        // Pre-canonicalization, " foo " normalized to the "_foo_" subdir; the canonical token is
        // "foo", so the old subdir must be copied forward or the upgrade strands shipped data.
        val old = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "_foo_"), baseDir = tmp, testEngine = FakeEncryption())
        old.put("k", "legacyDir")
        delay(300); old.close(); delay(100)
        assertTrue(File(tmp, "_foo_/$pbName").exists(), "precondition: data seeded under the legacy dir token")

        val upgraded = KSafe(fileName = "data", config = KSafeConfig(appNamespace = " foo "), baseDir = tmp, lazyLoad = true, testEngine = FakeEncryption())
        assertEquals("legacyDir", upgraded.get("k", "?"), "data under the pre-canonicalization subdir must carry forward")
        upgraded.close()
        assertTrue(File(tmp, "_foo_/$pbName").exists(), "carry-forward must COPY, leaving the legacy original")
    }

    @Test
    fun lossyNamespaceToken_carriesThePreDigestSubdirForward() = runTest {
        // Pre-digest releases normalized "a b" to the "a_b" subdir; the canonical token now carries
        // a collision digest, so "a b" and "a?b" cannot share one identity.
        val old = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "a_b"), baseDir = tmp, testEngine = FakeEncryption())
        old.put("k", "preDigest")
        delay(300); old.close(); delay(100)
        assertTrue(File(tmp, "a_b/$pbName").exists(), "precondition: data seeded under the pre-digest dir token")

        val upgraded = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "a b"), baseDir = tmp, lazyLoad = true, testEngine = FakeEncryption())
        assertEquals("preDigest", upgraded.get("k", "?"), "data under the pre-digest subdir must carry forward")
        upgraded.close()
        assertTrue(File(tmp, "a_b/$pbName").exists(), "carry-forward must COPY, leaving the legacy original")
    }

    @Test
    fun whitespaceOnlyNamespaceToken_mapsToTheUnNamespacedPath_andCarriesOldSubdirData() = runTest {
        // "___" is what a whitespace-only token normalized to pre-canonicalization.
        val old = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "___"), baseDir = tmp, testEngine = FakeEncryption())
        old.put("k", "fromLegacy")
        delay(300); old.close(); delay(100)

        // A whitespace-only token now cancels out entirely, matching the vault side.
        val ws = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "   "), baseDir = tmp, lazyLoad = true, testEngine = FakeEncryption())
        assertEquals("fromLegacy", ws.get("k", "?"), "old '___' subdir data must surface at the un-namespaced path")
        ws.close()
        assertTrue(File(tmp, pbName).exists(), "a whitespace-only token must use the un-namespaced path")
    }

    @Test
    fun existingUnNamespacedDataMigratesIntoTheNamespaceSubdir() = runTest {
        val old = KSafe(fileName = "data", baseDir = tmp, testEngine = FakeEncryption())
        old.put("k", "seeded")
        delay(300); old.close(); delay(200)
        assertTrue(File(tmp, pbName).exists(), "precondition: seeded at the un-namespaced path")

        val migrated = KSafe(fileName = "data", config = KSafeConfig(appNamespace = "appx"), baseDir = tmp, lazyLoad = true, testEngine = FakeEncryption())
        assertEquals(
            "seeded", migrated.get("k", "?"),
            "existing un-namespaced data must be migrated into the namespace subdir",
        )
        assertTrue(File(tmp, "appx/$pbName").exists(), "migrated copy must exist in the subdir")
        // Copy, not move, so a second app reading the old path can't lose its data.
        assertTrue(File(tmp, pbName).exists(), "migration must COPY, leaving the original")
        migrated.close()
    }
}
