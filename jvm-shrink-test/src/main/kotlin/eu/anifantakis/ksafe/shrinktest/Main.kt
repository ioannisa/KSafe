package eu.anifantakis.ksafe.shrinktest

import eu.anifantakis.lib.ksafe.KSafe
import eu.anifantakis.lib.ksafe.KSafeConfig
import eu.anifantakis.lib.ksafe.KSafeProtectionLevel
import eu.anifantakis.lib.ksafe.invoke
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.io.File
import kotlin.system.exitProcess

@Serializable
data class Address(val city: String)

@Serializable
data class Profile(val name: String, val age: Int, val tags: List<String>, val address: Address?)

@Serializable
enum class Tier { @SerialName("gold") GOLD, SILVER }

// No @Serializable: works because this module applies the serialization plugin.
enum class Theme { DARK, LIGHT }

@Serializable
@JvmInline
value class UserId(val raw: String)

@Serializable
sealed interface Shape {
    @Serializable
    @SerialName("circle")
    data class Circle(val radius: Double) : Shape

    // No @SerialName: the stored discriminator is the class's source name, whatever R8 renames it to.
    @Serializable
    data class Square(val side: Double) : Shape
}

@Serializable
data object Guest

class Prefs(ksafe: KSafe) {
    var counter by ksafe(0)
    var theme by ksafe(Theme.LIGHT)
    var profile by ksafe(Profile("", 0, emptyList(), null))
}

private val expectedProfile = Profile("Ioannis", 40, listOf("a", "b"), Address("Heraklion"))

private val failures = mutableListOf<String>()

private fun check(what: String, actual: Any?, expected: Any?) {
    val ok = actual == expected
    println("${if (ok) "ok  " else "FAIL"} $what = $actual")
    if (!ok) failures += "$what: expected $expected, got $actual"
}

// The namespace follows the directory's full path: the two runs of a cross-build pair share the
// OS-store keys, and a run in another checkout does not.
internal fun shrinkTestNamespace(dir: File) =
    "ksafe-shrink-${dir.name}-${Integer.toHexString(dir.absolutePath.hashCode())}"

private fun open(dir: File) =
    KSafe(fileName = "shrinktest", baseDir = dir, config = KSafeConfig(appNamespace = shrinkTestNamespace(dir)))

private fun checkOsStore(ksafe: KSafe) {
    val info = ksafe.protectionInfo
    println("custody: ${info.custody}")
    check("effectiveLevel", info.effectiveLevel, KSafeProtectionLevel.SANDBOX_PROTECTED)
    check("notes", info.notes, emptyList<String>())
}

private fun write(ksafe: KSafe) {
    Prefs(ksafe).apply {
        counter = 42
        theme = Theme.DARK
        profile = expectedProfile
    }
    runBlocking {
        ksafe.put("tier", Tier.GOLD)
        ksafe.put("userId", UserId("u-1"))
        ksafe.put<Shape>("circle", Shape.Circle(1.5))
        ksafe.put<Shape>("square", Shape.Square(2.0))
        ksafe.put("guest", Guest)
        ksafe.put("ids", listOf(UserId("a"), UserId("b")))
        ksafe.put("addresses", mapOf("home" to Address("Chania")))
        // Writes commit in order, so this returning means the delegates' writes are on disk too.
        ksafe.put("flush", true)
    }
}

private fun read(ksafe: KSafe, label: String) {
    val prefs = Prefs(ksafe)
    check("$label getDirect(\"counter\")", ksafe.getDirect("counter", -1), 42)
    check("$label delegate counter", prefs.counter, 42)
    check("$label theme", prefs.theme, Theme.DARK)
    check("$label profile", prefs.profile, expectedProfile)
    check("$label tier", ksafe.getDirect("tier", Tier.SILVER), Tier.GOLD)
    check("$label userId", ksafe.getDirect("userId", UserId("")), UserId("u-1"))
    check("$label circle", ksafe.getDirect<Shape>("circle", Shape.Square(0.0)), Shape.Circle(1.5))
    check("$label square", ksafe.getDirect<Shape>("square", Shape.Circle(0.0)), Shape.Square(2.0))
    check("$label guest", ksafe.getDirect<Guest?>("guest", null), Guest)
    check("$label ids", ksafe.getDirect("ids", emptyList<UserId>()), listOf(UserId("a"), UserId("b")))
    check("$label addresses", ksafe.getDirect("addresses", emptyMap<String, Address>()), mapOf("home" to Address("Chania")))
    check("$label getKeyInfo(\"counter\").level", ksafe.getKeyInfo("counter")?.level, KSafeProtectionLevel.SANDBOX_PROTECTED)
}

// Runs from a shrunk or unshrunk jar on a host with a reachable OS secret store, and exits non-zero
// unless KSafe uses that store and every value reads back. Phases: `all` writes and reads back in a
// fresh instance; `write` leaves the store for a `read` by another build of the app, which then
// deletes it.
fun main(args: Array<String>) {
    val dir = File(args[0])
    when (val phase = args.getOrElse(1) { "all" }) {
        "write", "all" -> {
            val first = open(dir)
            checkOsStore(first)
            write(first)
            read(first, "same instance")
            first.close()
            if (phase == "all") {
                // A fresh instance has to fetch the keys back from the OS store to decrypt.
                val second = open(dir)
                try {
                    read(second, "reopened")
                } finally {
                    runBlocking { second.clearAll() }
                    second.close()
                }
            }
        }
        "read" -> {
            val ksafe = open(dir)
            try {
                checkOsStore(ksafe)
                read(ksafe, "other build")
            } finally {
                runBlocking { ksafe.clearAll() }
                ksafe.close()
            }
        }
        else -> error("Unknown phase $phase")
    }

    if (failures.isNotEmpty()) {
        System.err.println("KSafe shrink test failed:\n" + failures.joinToString("\n"))
        exitProcess(1)
    }
    exitProcess(0)
}
