package eu.anifantakis.lib.ksafe

import kotlin.test.AfterTest
import kotlin.uuid.ExperimentalUuidApi

/**
 * Locks in: the common [KSafeTest] suite against the macOS implementation, each test
 * on a fresh [KSafe] over a unique temp directory. Uses [FakeEncryption] because the
 * unsigned Kotlin/Native test runner can't touch the login Keychain without failing
 * opaquely or triggering an interactive password prompt.
 */
@OptIn(ExperimentalUuidApi::class)
class MacosKSafeTest : KSafeTest() {

    private val tempDirs = mutableListOf<String>()

    override fun newKSafe(fileName: String?): KSafe {
        val actualFileName = fileName ?: MacosTestPaths.uniqueFileName("macosksafe")
        val tempDir = MacosTestPaths.uniqueTempDir("macos-ksafe-test")
        tempDirs += tempDir
        return KSafe(
            fileName = actualFileName,
            directory = tempDir,
            testEngine = FakeEncryption(),
        )
    }

    // Named to sort after tearDown (alphabetical), so every KSafe is closed and its
    // DataStore writer flushed before the directories are deleted.
    @AfterTest
    fun zCleanupTempDirs() {
        tempDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        tempDirs.clear()
    }
}
