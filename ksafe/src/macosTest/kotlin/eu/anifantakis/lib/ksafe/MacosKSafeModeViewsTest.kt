package eu.anifantakis.lib.ksafe

import kotlin.test.AfterTest
import kotlin.uuid.ExperimentalUuidApi

/** macOS (native) binding for the shared mode-views suite. */
@OptIn(ExperimentalUuidApi::class)
class MacosKSafeModeViewsTest : KSafeModeViewsTest() {

    private val tempDirs = mutableListOf<String>()

    override fun newKSafe(fileName: String?): KSafe {
        val name = fileName ?: MacosTestPaths.uniqueFileName("macosmodeviews")
        val dir = MacosTestPaths.uniqueTempDir("macos-ksafe-modeviews")
        tempDirs += dir
        return KSafe(fileName = name, directory = dir, testEngine = FakeEncryption())
    }

    @AfterTest
    fun zCleanupTempDirs() {
        tempDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        tempDirs.clear()
    }
}
