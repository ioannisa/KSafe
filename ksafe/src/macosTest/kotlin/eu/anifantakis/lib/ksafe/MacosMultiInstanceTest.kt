package eu.anifantakis.lib.ksafe

import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.uuid.ExperimentalUuidApi

/**
 * Locks in: the Apple factory shares one ref-counted DataStore per file path, so
 * co-existing [KSafe] instances on the same file (and close-then-recreate) read and
 * write the same store instead of tripping native DataStore's multiple-active guard.
 */
@OptIn(ExperimentalUuidApi::class)
class MacosMultiInstanceTest {

    private val tempDirs = mutableListOf<String>()

    private fun dir(): String = MacosTestPaths.uniqueTempDir("macos-multi").also { tempDirs += it }

    @AfterTest
    fun cleanup() {
        tempDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        tempDirs.clear()
    }

    @Test
    fun twoLiveInstances_sameFile_bothReadAndWrite() = runBlocking {
        val file = "multi"
        val d = dir()
        val a = KSafe(fileName = file, directory = d, testEngine = FakeEncryption())
        val b = KSafe(fileName = file, directory = d, testEngine = FakeEncryption())

        a.put("ka", "va")
        assertEquals("va", b.get("ka", "none"), "a co-existing same-file instance must read the shared store")

        b.put("kb", "vb")
        a.close(); b.close()

        val c = KSafe(fileName = file, directory = d, testEngine = FakeEncryption())
        assertEquals("va", c.get("ka", "none"))
        assertEquals("vb", c.get("kb", "none"), "the second instance's write must have persisted")
        c.close()
    }

    @Test
    fun closeThenRecreate_sameFile_dataPersists() = runBlocking {
        val file = "recreate"
        val d = dir()
        repeat(15) { i ->
            val ks = KSafe(fileName = file, directory = d, testEngine = FakeEncryption())
            ks.put("counter", "v$i")
            assertEquals("v$i", ks.get("counter", "none"))
            ks.close()
        }
        val reopened = KSafe(fileName = file, directory = d, testEngine = FakeEncryption())
        assertEquals("v14", reopened.get("counter", "none"), "data must persist across close→recreate")
        reopened.close()
    }
}
