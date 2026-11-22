package eu.anifantakis.ksafe.shrinktest.biometrics

import com.sun.jna.Callback
import com.sun.jna.CallbackReference
import eu.anifantakis.lib.ksafe.biometrics.KSafeBiometrics
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.io.PrintStream
import kotlin.system.exitProcess

// The lines the biometric bridges print when their JNA layer is broken, not when the OS simply has
// no biometrics set up.
private val bridgeFailures = listOf("bridge unavailable (", "bridge failed to load", "prompt failed (", "check failed (")

private fun <T> call(block: suspend () -> T): Result<T> = runCatching { runBlocking { withTimeout(60_000) { block() } } }

private fun Result<*>.describe() = getOrElse { it::class.java.name }.toString()

// The Touch ID reply block's type, by name: JNA must still find its single method after shrinking.
private const val REPLY_CALLBACK = "eu.anifantakis.lib.ksafe.biometrics.MacLocalAuthentication\$LAReplyCallback"

// Runs from a shrunk or unshrunk jar and never shows a prompt. Exits non-zero if a bridge is broken;
// result.txt lets the build compare the shrunk answers with the unshrunk ones on the same host.
// args: work dir, then for a shrunk run the unshrunk run's work dir.
fun main(args: Array<String>) {
    val resultFile = File(args[0], "result.txt")
    // Whether this host would prompt comes from the unshrunk run: a broken shrunk bridge can read
    // "no Touch ID" where there is one.
    val unshrunkStrict = args.getOrNull(1)?.let { File(it, "result.txt").readText().contains("available strict=true") }
    val captured = ByteArrayOutputStream()
    val stderr = System.err
    System.setErr(PrintStream(object : OutputStream() {
        override fun write(b: Int) { stderr.write(b); captured.write(b) }
    }, true))

    val results = mutableListOf<String>()
    val failures = mutableListOf<String>()
    fun expect(what: String, actual: Result<Boolean>, expected: Boolean) {
        results += "$what=${actual.describe()}"
        if (actual.getOrNull() != expected) failures += "$what: expected $expected, got ${actual.describe()}"
    }

    if (System.getProperty("ksafe.biometrics.jvm.prompts") != null || System.getenv("KSAFE_BIOMETRICS_JVM_PROMPTS") != null) {
        failures += "the prompts opt-out is set, so no bridge would be exercised"
    }
    val os = System.getProperty("os.name").lowercase()
    val strict = call { KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = false) }
    val permissive = call { KSafeBiometrics.biometricsAvailable(allowDeviceCredentialFallback = true) }
    results += "available strict=${strict.describe()} permissive=${permissive.describe()}"
    if (strict.isFailure || permissive.isFailure) failures += "biometricsAvailable threw"

    // Binds the reply block the way a prompt would, without one: works on every OS and on a Mac
    // with Touch ID, where the strict request below is skipped.
    val replyBinds = runCatching {
        val type = Class.forName(REPLY_CALLBACK)
        // JNA keeps the callback in a map, so the proxy needs identity hashCode and equals.
        val reply = java.lang.reflect.Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { proxy, method, args ->
            when (method.name) {
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.get(0)
                "toString" -> "reply callback"
                else -> null
            }
        }
        CallbackReference.getFunctionPointer(reply as Callback) != null
    }
    results += "reply callback binds=${replyBinds.describe()}"
    if (replyBinds.getOrNull() != true) failures += "reply callback: ${replyBinds.exceptionOrNull() ?: "no pointer"}"

    when {
        // Without Touch ID a strict request resolves at once through the reply callback, so the whole
        // native round trip runs without a prompt. With Touch ID it would prompt, so it is skipped.
        os.contains("mac") -> if ((unshrunkStrict ?: strict.getOrNull()) == false) {
            expect("strict verify", call { KSafeBiometrics.verifyBiometric("KSafe shrink test", allowDeviceCredentialFallback = false) }, false)
        } else {
            results += "strict verify=skipped"
        }
        // Windows: availability only. How far its COM round trip gets depends on the runner's Hello.
        os.contains("windows") -> results += "strict verify=skipped"
        // No prompt path: both modes pass through without touching the OS.
        else -> {
            expect("strict verify", call { KSafeBiometrics.verifyBiometric("KSafe shrink test", allowDeviceCredentialFallback = false) }, true)
            expect("permissive verify", call { KSafeBiometrics.verifyBiometric("KSafe shrink test") }, true)
        }
    }

    System.err.flush()
    val lines = captured.toString().lines().filter { it.startsWith("KSafe biometrics:") }
    lines.filter { line -> bridgeFailures.any { it in line } }.forEach { failures += "bridge: $it" }
    if (!os.contains("mac") && !os.contains("windows")) lines.forEach { failures += "unexpected: $it" }

    results.forEach { println("result $it") }
    resultFile.writeText(results.joinToString("\n"))
    if (failures.isNotEmpty()) {
        stderr.println("KSafe biometrics shrink test failed:\n" + failures.joinToString("\n"))
        exitProcess(1)
    }
    exitProcess(0)
}
