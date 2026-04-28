package eu.anifantakis.lib.ksafe

import kotlin.test.AfterTest
import kotlin.uuid.ExperimentalUuidApi

/**
 * Runs the full common [KSafeTest] suite against the macOS implementation.
 *
 * Each test gets a freshly created [KSafe] backed by [FakeEncryption] (no
 * real Keychain access — see class doc) and a unique temporary storage
 * directory (no real `~/Library/Application Support/` writes). All temp
 * directories created during a test are cleaned up at teardown.
 *
 * **Why FakeEncryption?** The Kotlin/Native test runner on macOS is an
 * unsigned CLI binary. `SecItemAdd`/`SecItemCopyMatching` against the
 * user's login Keychain on such a binary either fails opaquely or
 * triggers an interactive system password prompt — neither is acceptable
 * for automated tests. Real-Keychain coverage on macOS belongs in an
 * integration test inside a properly signed/entitled application bundle,
 * not in the unit-test runner.
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

    /**
     * Runs after [KSafeTest.tearDown] (alphabetical order — `zCleanupTempDirs`
     * comes after `tearDown`), so all KSafe instances have been closed and
     * their DataStore writers flushed before we yank the directories.
     */
    @AfterTest
    fun zCleanupTempDirs() {
        tempDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        tempDirs.clear()
    }
}
