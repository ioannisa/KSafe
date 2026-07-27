package eu.anifantakis.lib.ksafe

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: [copyStoreFilesForward] publishes the namespace carry-forward as ONE coherent,
 * atomically-published cohort — a mid-cohort copy failure leaves no final name occupied (so
 * the next launch retries instead of a truncated destination blocking it forever), and the
 * whole cohort comes from a single source directory (mixing sources could pair a data file
 * with a foreign key sidecar, or carry a foreign `.migrated` marker that defeats the
 * fallback-migration mtime gate).
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

        // Fail the SECOND copy of the cohort.
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

        // Next launch: the retry is not blocked and completes the whole cohort.
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
        // The base dir holds a DIFFERENT logical store sharing the baseFileName — including a
        // fresh `.migrated` marker that, if mixed in, would defeat the fallback-migration
        // mtime gate of the copied legacy store.
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
        // The `.migration-pending` marker is what tells the next launch that a fallback drain
        // already failed once, so newer store values must not be rolled back. Publishing the
        // fallback JSON without it re-arms the unconditional "fallback wins" path.
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

        // The next launch is not blocked: it re-copies and publishes the whole cohort.
        copyStoreFilesForward(listOf(src), dst, base)
        assertTrue(File(dst, "$base.ksafe.json").exists(), "retry must publish the data file")
        assertTrue(
            File(dst, "$base.ksafe.json.migration-pending").exists(),
            "retry must publish the marker",
        )
    }

    @Test
    fun whicheverPublishFails_theFallbackDataFileNeverAppearsAlone() {
        // The general invariant behind the ordering: the fallback JSON is the file whose mere
        // presence makes the next launch act, so it may only appear once everything it depends
        // on — both markers, its key sidecar, the store file it must not overwrite — is in place.
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
}
