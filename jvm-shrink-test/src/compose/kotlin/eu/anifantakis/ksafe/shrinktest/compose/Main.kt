package eu.anifantakis.ksafe.shrinktest.compose

import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.KSafeProtectionLevel
import eu.anifantakis.lib.ksafe.compose.mutableStateOf
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.system.exitProcess

class ComposePrefs(ksafe: KSafe) {
    var nickname by ksafe.mutableStateOf("anon")
}

private val failures = mutableListOf<String>()

private fun check(what: String, actual: Any?, expected: Any?) {
    val ok = actual == expected
    println("${if (ok) "ok  " else "FAIL"} $what = $actual")
    if (!ok) failures += "$what: expected $expected, got $actual"
}

private fun open(dir: File) = KSafe(
    fileName = "shrinktest",
    baseDir = dir,
    config = KSafeConfig(appNamespace = "ksafe-shrink-${dir.name}-${Integer.toHexString(dir.absolutePath.hashCode())}"),
)

// A Compose Desktop app's use of ksafe-compose, shrunk: a mutableStateOf delegate must save under
// the property's name, in the OS store, and come back in a fresh instance.
fun main(args: Array<String>) {
    val dir = File(args[0])
    val first = open(dir)
    try {
        check("effectiveLevel", first.protectionInfo.effectiveLevel, KSafeProtectionLevel.SANDBOX_PROTECTED)
        val prefs = ComposePrefs(first)
        prefs.nickname = "Ioannis"
        check("state nickname", prefs.nickname, "Ioannis")
        // Writes commit in order, so this returning means the delegate's write is on disk too.
        runBlocking { first.put("flush", true) }
        check("getDirect(\"nickname\")", first.getDirect("nickname", ""), "Ioannis")
    } finally {
        first.close()
    }
    val second = open(dir)
    try {
        check("reopened nickname", ComposePrefs(second).nickname, "Ioannis")
    } finally {
        runBlocking { second.clearAll() }
        second.close()
    }
    if (failures.isNotEmpty()) {
        System.err.println("KSafe compose shrink test failed:\n" + failures.joinToString("\n"))
        exitProcess(1)
    }
    exitProcess(0)
}
