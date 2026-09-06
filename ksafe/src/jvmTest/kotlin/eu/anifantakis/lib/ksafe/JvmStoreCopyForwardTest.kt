package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.DATASTORE_FILE_SUFFIX
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: [copyStoreFilesForward] publishes the namespace carry-forward as one atomic cohort — a
 * mid-cohort failure occupies no final name, so the next launch retries, and the cohort comes from
 * a single source directory, since mixing sources could pair a data file with a foreign key sidecar
 * or `.migrated` marker. A file caught in the backend's rewrite window is waited for, not skipped.
 */
class JvmStoreCopyForwardTest {

    private val tmp: File = Files.createTempDirectory("ksafe-copyfwd").toFile()
    private val base = "eu_anifantakis_ksafe_datastore_data"

    @AfterTest
    fun tearDown() {
        tmp.deleteRecursively()
    }

    private fun dir(name: String): File = File(tmp, name).apply { mkdirs() }

    @Test
    fun midCohortCopyFailure_leavesNoFinalNames_andRetrySucceeds() {
        val src = dir("src").also {
            File(it, "$base.ksafe.json").writeText("{\"data\":1}")
            File(it, "$base.ksafe-keys.json").writeText("{\"keys\":1}")
        }
        val dst = dir("dst")

        var copies = 0
        copyStoreFilesForward(listOf(src), dst, base) { s, d ->
            if (++copies == 2) throw java.io.IOException("injected copy failure")
            s.copyTo(d, overwrite = true)
        }

        val finalNames = dst.listFiles()!!.map { it.name }.filterNot { it.endsWith(".fwd-tmp") }
        assertTrue(finalNames.isEmpty(), "a failed cohort must occupy NO final names, was: $finalNames")
        assertTrue(
            dst.listFiles()!!.none { it.name.endsWith(".fwd-tmp") },
            "staging temps must be cleaned up after a failure",
        )

        copyStoreFilesForward(listOf(src), dst, base)
        assertTrue(File(dst, "$base.ksafe.json").exists(), "retry must copy the data file")
        assertTrue(File(dst, "$base.ksafe-keys.json").exists(), "retry must copy the key sidecar")
    }

    @Test
    fun cohortComesFromOneSourceDirectory_neverMixed() {
        // The preferred (legacy-namespace) dir holds the real store: data + keys.
        val legacyDir = dir("legacy").also {
            File(it, "$base.ksafe.json").writeText("{\"from\":\"legacy\"}")
            File(it, "$base.ksafe-keys.json").writeText("{\"keys\":\"legacy\"}")
        }
        // The base dir holds a different logical store sharing the baseFileName, including a fresh
        // `.migrated` marker that if mixed in would defeat the copied store's mtime gate.
        val baseDir = dir("base").also {
            File(it, "$base.ksafe-keys.json").writeText("{\"keys\":\"foreign\"}")
            File(it, "$base.ksafe.json.migrated").writeText("foreign-archive")
        }
        val dst = dir("dst2")

        copyStoreFilesForward(listOf(legacyDir, baseDir), dst, base)

        assertEquals(
            "{\"keys\":\"legacy\"}", File(dst, "$base.ksafe-keys.json").readText(),
            "the key sidecar must come from the SAME source dir as the data file",
        )
        assertFalse(
            File(dst, "$base.ksafe.json.migrated").exists(),
            "a foreign source dir's `.migrated` marker must not ride along with another dir's cohort",
        )
    }

    @Test
    fun aFailedMarkerPublish_neverLeavesTheFallbackDataFileVisibleWithoutIt() {
        // The `.migration-pending` marker tells the next launch a drain already failed once, so
        // newer store values stay. Publishing the fallback JSON without it re-arms "fallback wins".
        val src = dir("src4").also {
            File(it, "$base.preferences_pb").writeText("newer-values")
            File(it, "$base.ksafe.json").writeText("{\"stale\":1}")
            File(it, "$base.ksafe-keys.json").writeText("{\"keys\":1}")
            File(it, "$base.ksafe.json.migration-pending").writeText("{}")
        }
        val dst = dir("dst4")

        // An in-process rename failure: same-directory renames fail on a file lock (AV, indexer).
        copyStoreFilesForward(
            listOf(src), dst, base,
            rename = { tmp, d -> if (d.name.endsWith(".migration-pending")) false else tmp.renameTo(d) },
        )

        assertFalse(
            File(dst, "$base.ksafe.json").exists(),
            "the fallback data file must not be visible without the marker that gates its drain",
        )
        assertTrue(
            dst.listFiles()!!.none { it.name.endsWith(".fwd-tmp") },
            "staging temps must not be left behind by a failed publish",
        )

        copyStoreFilesForward(listOf(src), dst, base)
        assertTrue(File(dst, "$base.ksafe.json").exists(), "retry must publish the data file")
        assertTrue(
            File(dst, "$base.ksafe.json.migration-pending").exists(),
            "retry must publish the marker",
        )
    }

    @Test
    fun whicheverPublishFails_theFallbackDataFileNeverAppearsAlone() {
        // The fallback JSON's mere presence makes the next launch act, so it may only appear once
        // everything it depends on — both markers, the key sidecar, the store file — is in place.
        val cohort = listOf(
            ".preferences_pb", ".ksafe.json", ".ksafe-keys.json",
            ".ksafe.json.migrated", ".ksafe.json.migration-pending",
        )
        for ((index, failing) in cohort.withIndex()) {
            val src = dir("src5_$index").also { d ->
                cohort.forEach { File(d, base + it).writeText("x") }
            }
            val dst = dir("dst5_$index")

            copyStoreFilesForward(
                listOf(src), dst, base,
                rename = { tmp, d -> if (d.name == base + failing) false else tmp.renameTo(d) },
            )

            if (File(dst, "$base.ksafe.json").exists()) {
                val missing = cohort.filterNot { File(dst, base + it).exists() }
                assertTrue(
                    missing.isEmpty(),
                    "publishing $failing failed and the fallback data file was still published " +
                        "without $missing",
                )
            }
        }
    }

    @Test
    fun copiedFiles_keepTheirSourceMtimes() {
        val now = System.currentTimeMillis()
        val src = dir("src3").also {
            File(it, "$base.ksafe.json").apply { writeText("{}"); setLastModified(now - 60_000) }
            File(it, "$base.ksafe.json.migrated").apply { writeText("a"); setLastModified(now - 120_000) }
        }
        val dst = dir("dst3")

        copyStoreFilesForward(listOf(src), dst, base)

        assertTrue(
            File(dst, "$base.ksafe.json").lastModified() > File(dst, "$base.ksafe.json.migrated").lastModified(),
            "copies must keep source mtimes so a newer fallback stays newer than the marker",
        )
    }

    @Test
    fun importOnce_publishesTheCohort_andNeverReCopiesAfterTheMarker() {
        val src = dir("src6").also {
            File(it, "$base.ksafe.json").writeText("{\"data\":1}")
            File(it, "$base.ksafe-keys.json").writeText("{\"keys\":1}")
        }
        val dst = dir("dst6")

        importStoreFilesOnce(listOf(src), dst, base)

        val marker = File(dst, base + NAMESPACE_IMPORT_MARKER_SUFFIX)
        assertTrue(marker.exists(), "a fully published import must leave the one-shot marker")
        assertTrue(File(dst, "$base.ksafe-keys.json").exists(), "the cohort must be published")

        // A later wipe removes the copies; the next launch must not bring them back.
        File(dst, "$base.ksafe.json").delete()
        File(dst, "$base.ksafe-keys.json").delete()
        importStoreFilesOnce(listOf(src), dst, base)
        assertFalse(File(dst, "$base.ksafe.json").exists(), "a completed import must not be repeated")
        assertFalse(File(dst, "$base.ksafe-keys.json").exists(), "a completed import must not re-copy the plaintext key map")
    }

    @Test
    fun importOnce_failedPublish_leavesNoMarker_soTheNextLaunchRetries() {
        val src = dir("src7").also {
            File(it, "$base.ksafe.json").writeText("{\"data\":1}")
            File(it, "$base.ksafe-keys.json").writeText("{\"keys\":1}")
        }
        val dst = dir("dst7")
        val marker = File(dst, base + NAMESPACE_IMPORT_MARKER_SUFFIX)

        var copies = 0
        importStoreFilesOnce(listOf(src), dst, base) { s, d ->
            if (++copies == 2) throw java.io.IOException("injected copy failure")
            s.copyTo(d, overwrite = true)
        }
        assertFalse(marker.exists(), "a failed publish must not be marked as imported")

        importStoreFilesOnce(listOf(src), dst, base)
        assertTrue(File(dst, "$base.ksafe.json").exists(), "retry must publish the data file")
        assertTrue(File(dst, "$base.ksafe-keys.json").exists(), "retry must publish the key sidecar")
        assertTrue(marker.exists(), "the successful retry must leave the marker")
    }

    @Test
    fun importOnce_nothingToCopy_leavesNoMarker_soALaterLaunchReScans() {
        val src = dir("src8")
        val dst = dir("dst8")

        assertTrue(importStoreFilesOnce(listOf(src), dst, base), "an empty source is not a failure")

        assertFalse(
            File(dst, base + NAMESPACE_IMPORT_MARKER_SUFFIX).exists(),
            "finding nothing must not permanently end the one-shot import: a store file sampled " +
                "mid-rewrite looks absent, and the marker would strand it forever",
        )
    }

    @Test
    fun importOnce_nothingToCopy_endsTheImportOnceTheDestinationHoldsItsOwnStore() {
        val src = dir("src9")
        val dst = dir("dst9").also { File(it, "$base$DATASTORE_FILE_SUFFIX").writeText("pb") }

        importStoreFilesOnce(listOf(src), dst, base)

        assertTrue(
            File(dst, base + NAMESPACE_IMPORT_MARKER_SUFFIX).exists(),
            "a destination that already holds the cohort ends the one-shot import",
        )
    }

    /**
     * DataStore's JVM rewrite is `unlink(target)` then `rename(scratch, target)`, so the store
     * file is briefly absent while its `.tmp` scratch sits beside it. Reproduces that window.
     */
    private fun startRewriteWindow(dir: File, suffix: String): Thread {
        val real = File(dir, base + suffix)
        val scratch = File(real.path + ".tmp")
        scratch.writeText("pb")
        real.delete()
        return Thread {
            Thread.sleep(20)
            scratch.renameTo(real)
        }.apply { isDaemon = true; start() }
    }

    @Test
    fun sourceSelection_waitsOutADataStoreRewriteWindow() {
        val src = dir("src10")
        val rewrite = startRewriteWindow(src, DATASTORE_FILE_SUFFIX)
        try {
            assertEquals(
                src, selectCopyForwardSource(listOf(src), base),
                "a store file caught mid-rewrite must not read as 'no cohort here'",
            )
        } finally {
            rewrite.join()
        }
    }

    @Test
    fun perFileSource_waitsOutADataStoreRewriteWindow_insteadOfSkippingTheStoreFile() {
        // The key sidecar selects the source directory outright, so the per-file check is what
        // meets the mid-rewrite store file.
        val src = dir("src11").also { File(it, "$base.ksafe-keys.json").writeText("{\"keys\":1}") }
        val dst = dir("dst11")
        val rewrite = startRewriteWindow(src, DATASTORE_FILE_SUFFIX)
        try {
            assertTrue(copyStoreFilesForward(listOf(src), dst, base), "the publish must succeed")
        } finally {
            rewrite.join()
        }

        assertTrue(
            File(dst, "$base$DATASTORE_FILE_SUFFIX").exists(),
            "a store file caught mid-rewrite must be waited for, not silently dropped from the cohort",
        )
    }
}
