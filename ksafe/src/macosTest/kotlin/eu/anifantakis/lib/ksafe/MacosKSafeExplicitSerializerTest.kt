package eu.anifantakis.lib.ksafe

import kotlin.test.AfterTest
import kotlin.uuid.ExperimentalUuidApi

/** macOS (native) binding for the shared explicit-serializer suite. */
@OptIn(ExperimentalUuidApi::class)
class MacosKSafeExplicitSerializerTest : KSafeExplicitSerializerTest() {

    private val tempDirs = mutableListOf<String>()

    override fun newKSafe(fileName: String?): KSafe {
        val name = fileName ?: MacosTestPaths.uniqueFileName("macosexplicit")
        val dir = MacosTestPaths.uniqueTempDir("macos-ksafe-explicit")
        tempDirs += dir
        return KSafe(fileName = name, directory = dir, testEngine = FakeEncryption())
    }

    @AfterTest
    fun zCleanupTempDirs() {
        tempDirs.forEach { runCatching { MacosTestPaths.deleteRecursively(it) } }
        tempDirs.clear()
    }
}
