package eu.anifantakis.ksafe.compose

import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.KSafeWriteMode
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks in: a Compose `mutableStateOf` write without an explicit mode inherits the instance's
 * `KSafeConfig.requireUnlockedDevice` (via `KSafe.defaultWriteMode`) instead of silently
 * downgrading to the relaxed `KSafeWriteMode.Encrypted()` literal. Observable in the persisted
 * per-entry metadata JSON, which records a strict unlock policy as `"u":"unlocked"` and omits
 * the field entirely for a relaxed write.
 */
class ComposeDefaultModeJvmTest {

    private val strictProbe: String = ""
    private val relaxedProbe: String = ""

    @Test
    fun mutableStateOf_defaultMode_inheritsInstanceRequireUnlockedDevice() {
        val dir = Files.createTempDirectory("ksafe-compose-mode").toFile()
        val ksafe = KSafe(
            fileName = "modestrict",
            config = KSafeConfig(requireUnlockedDevice = true),
            baseDir = dir,
        )
        try {
            val provider = ksafe.mutableStateOf("d", key = "strict_probe_key")
            val delegate = provider.provideDelegate(null, ::strictProbe)
            delegate.setValue(null, ::strictProbe, "v")
            // FIFO flush: when this suspend put returns, the delegate write is durable.
            runBlocking { ksafe.put("__flush__", "x", KSafeWriteMode.Plain) }

            val text = persistedText(dir)
            assertTrue(text.contains("strict_probe_key"), "the write must have been persisted")
            assertTrue(
                text.contains("\"u\":\"unlocked\""),
                "a modeless Compose write on a strict instance must persist requireUnlockedDevice=true metadata",
            )
        } finally {
            ksafe.close()
            dir.deleteRecursively()
        }
    }

    @Test
    fun mutableStateOf_defaultMode_staysRelaxed_withDefaultConfig() {
        val dir = Files.createTempDirectory("ksafe-compose-mode").toFile()
        val ksafe = KSafe(fileName = "moderelaxed", baseDir = dir)
        try {
            val provider = ksafe.mutableStateOf("d", key = "relaxed_probe_key")
            val delegate = provider.provideDelegate(null, ::relaxedProbe)
            delegate.setValue(null, ::relaxedProbe, "v")
            runBlocking { ksafe.put("__flush__", "x", KSafeWriteMode.Plain) }

            val text = persistedText(dir)
            assertTrue(text.contains("relaxed_probe_key"), "the write must have been persisted")
            assertFalse(
                text.contains("\"u\":\"unlocked\""),
                "with the default config a modeless Compose write must stay requireUnlockedDevice=false",
            )
        } finally {
            ksafe.close()
            dir.deleteRecursively()
        }
    }

    private fun persistedText(dir: File): String =
        dir.walkTopDown().filter { it.isFile }.joinToString("\n") { it.readText(Charsets.ISO_8859_1) }
}
