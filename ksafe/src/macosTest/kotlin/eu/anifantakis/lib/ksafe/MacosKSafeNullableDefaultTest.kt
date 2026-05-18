package eu.anifantakis.lib.ksafe

import kotlin.test.AfterTest
import kotlin.uuid.ExperimentalUuidApi

/** macOS (native) binding for the issue #31 regression suite. */
@OptIn(ExperimentalUuidApi::class)
class MacosKSafeNullableDefaultTest : KSafeNullableDefaultTest() {

    private val tempDirs = mutableListOf<String>()

    override fun newKSafe(fileName: String?): KSafe {
        val name = fileName ?: MacosTestPaths.uniqueFileName("macosnulldef")
        val dir = MacosTestPaths.uniqueTempDir("macos-ksafe-nulldef")
        tempDirs += dir
        return KSafe(fileName = name, directory = dir, testEngine = FakeEncryption())
    }

    @AfterTest
    fun zCleanupTempDirs() {
        tempDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        tempDirs.clear()
    }
}
