package eu.anifantakis.lib.ksafe

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import eu.anifantakis.lib.ksafe.internal.DATASTORE_FILE_SUFFIX
import eu.anifantakis.lib.ksafe.internal.KSafeSecretSlots
import eu.anifantakis.lib.ksafe.internal.dataStoreBaseFileName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Locks in: the startup orphan-ciphertext sweep never reaps a `getOrCreateSecret` slot. The
 * refuse-to-rotate guard asks "is the ciphertext still there?", so sweeping the slot when its key is
 * gone (backup restore, Keystore invalidation, an evicted web CryptoKey) turns the guard into a
 * silent rotation — a fresh secret is handed back and the database it keyed is locked forever.
 */
class JvmSecretSurvivesOrphanSweepTest {

    private val tmp = File(
        System.getProperty("java.io.tmpdir"),
        "ksafe_secret_sweep_${System.nanoTime()}",
    ).apply { mkdirs() }

    @AfterTest
    fun tearDown() {
        tmp.deleteRecursively()
    }

    private class Restored(val original: ByteArray, val ksafe: KSafe)

    /**
     * Reopens a store holding a secret and an ordinary entry against an empty vault — the
     * restored-onto-a-new-device shape — and returns once the sweep has reaped the ordinary entry.
     */
    private suspend fun restoreWithoutKeys(): Restored {
        val fileName = JvmKSafeTest.generateUniqueFileName()
        val log = ByteArrayOutputStream()
        lateinit var original: ByteArray
        lateinit var second: KSafe
        val swept = capturingStdout(log) {
            val first = KSafe(fileName = fileName, baseDir = tmp, testEngine = StatefulFakeEncryption())
            original = first.getOrCreateSecret("main_db")
            // Same per-entry alias shape as the secret slot, so it is a genuine orphan next session;
            // its disappearance is the "the sweep has run" signal.
            first.put("canary", "v", KSafeWriteMode.Encrypted(KSafeEncryptedProtection.HARDWARE_ISOLATED))
            first.close()

            second = KSafe(fileName = fileName, baseDir = tmp, testEngine = StatefulFakeEncryption())
            awaitCanaryReaped(second)
        }
        if (!swept) {
            fail(
                "premise: the startup orphan sweep must run and reap the ordinary orphan\n" +
                    diagnose(second, fileName, log.toString()),
            )
        }
        return Restored(original, second)
    }

    private suspend fun awaitCanaryReaped(ksafe: KSafe): Boolean = withTimeoutOrNull(20_000) {
        var clear = 0
        while (clear < 2) {
            clear = if (ksafe.getKeyInfo("canary") == null) clear + 1 else 0
            delay(25)
        }
        true
    } ?: false

    private suspend fun <T> capturingStdout(into: ByteArrayOutputStream, block: suspend () -> T): T {
        val original = System.out
        System.setOut(PrintStream(into, true))
        try {
            return block()
        } finally {
            System.setOut(original)
        }
    }

    /**
     * What a premise timeout needs to explain itself: the store on disk and in DataStore, the cache
     * and cleanup state, the library's log lines, and any dispatcher worker that is not idle.
     */
    private suspend fun diagnose(second: KSafe, fileName: String, logged: String): String {
        val core = second.core
        val fileKeys = withTimeoutOrNull(5_000) { storeFileKeys(fileName) } ?: setOf("<file read timed out>")
        // The JSON-file fallback backend has no DataStore behind it, so asking for one throws.
        val storeKeys = runCatching {
            withTimeoutOrNull(5_000) { second.dataStore.data.first().asMap().keys.map { it.name }.toSet() }
                ?: setOf("<DataStore read timed out>")
        }.getOrElse { setOf("<DataStore view unavailable: ${it::class.simpleName}>") }
        val canaryInFlight = core.commitInFlight?.let { if (it.isCompleted) "completed" else "OPEN" } ?: "none"
        val sweep = core.startupSweepFailure?.let { "threw ${it::class.simpleName}: ${it.message}" }
            ?: when {
                core.startupSweepFinished.get() -> "completed"
                core.startupCleanupDone.get() -> "started, still running"
                else -> "never started"
            }
        return buildString {
            appendLine("store file holds canary: ${fileKeys.any { "canary" in it }}; raw keys on disk: ${fileKeys.sorted()}")
            appendLine("DataStore holds canary: ${storeKeys.any { "canary" in it }}; raw keys it reports: ${storeKeys.sorted()}")
            appendLine("getKeyInfo(canary)=${second.getKeyInfo("canary")}")
            appendLine(
                "memoryCache canary keys=${core.memoryCache.snapshot().keys.filter { "canary" in it }} " +
                    "protectionMap[canary]=${core.protectionMap["canary"]} encMetaMap[canary]=${core.encMetaMap["canary"]} " +
                    "dirtyKeys=${core.dirtyKeys.snapshot()}",
            )
            appendLine(
                "sweep: $sweep; startupCleanupDone=${core.startupCleanupDone.get()} " +
                    "cacheInitialized=${core.cacheInitialized.get()} " +
                    "closing=${core.closing.get()} commitInFlight=$canaryInFlight " +
                    "collectorScope.isActive=${core.collectorScope.isActive} writeScope.isActive=${core.writeScope.isActive}",
            )
            appendLine("library output during the test:")
            appendLine(logged.lines().filter { "KSafe" in it }.joinToString("\n").ifEmpty { "  (none)" })
            appendLine("dispatcher workers not idle:")
            append(busyWorkerStacks().ifEmpty { "  (none)" })
        }
    }

    /** The raw keys the store file holds, parsed by DataStore from a copy: the live instance owns
     *  the file, and DataStore refuses a second instance on it. */
    private suspend fun storeFileKeys(fileName: String): Set<String> {
        val storeFile = File(tmp, dataStoreBaseFileName(fileName) + DATASTORE_FILE_SUFFIX)
        if (!storeFile.exists()) return setOf("<no store file ${storeFile.name}>")
        val copy = storeFile.copyTo(File(tmp, "diag_" + storeFile.name), overwrite = true)
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            return PreferenceDataStoreFactory.create(scope = scope, produceFile = { copy })
                .data.first().asMap().keys.map { it.name }.toSet()
        } finally {
            scope.cancel()
        }
    }

    /** Stacks of dispatcher workers that are not parked idle — a worker stuck in a blocking wait shows here. */
    private fun busyWorkerStacks(): String = Thread.getAllStackTraces()
        .filterKeys { it.name.startsWith("DefaultDispatcher-worker") }
        .filterValues { frames ->
            frames.none { it.className == "kotlinx.coroutines.scheduling.CoroutineScheduler\$Worker" && it.methodName == "park" }
        }
        .entries.joinToString("\n") { (thread, frames) ->
            "  ${thread.name} [${thread.state}]\n" + frames.take(16).joinToString("\n") { "    at $it" }
        }

    @Test
    fun secretSlotSurvivesTheOrphanSweep_soTheRefuseToRotateGuardStillFires() = runBlocking {
        val restored = restoreWithoutKeys()

        assertNotNull(
            restored.ksafe.getKeyInfo("ksafe_secret_main_db"),
            "the secret slot's ciphertext must survive the orphan sweep — once it is gone the " +
                "refuse-to-rotate guard sees \"no secret\" and mints a replacement",
        )

        val ex = runCatching { restored.ksafe.getOrCreateSecret("main_db") }.exceptionOrNull()
        assertIs<IllegalStateException>(ex, "an unreadable existing secret must throw, not rotate")
        assertTrue(
            ex.message?.contains("Refusing to overwrite") == true,
            "must surface the refuse-to-rotate failure; was: ${ex.message}",
        )

        restored.ksafe.close()
    }

    @Test
    fun afterTheSweep_getOrCreateSecretNeverHandsBackADifferentSecret() = runBlocking {
        val restored = restoreWithoutKeys()

        val outcome = runCatching { restored.ksafe.getOrCreateSecret("main_db") }
        val returned = outcome.getOrNull()
        assertTrue(
            returned == null || returned.contentEquals(restored.original),
            "getOrCreateSecret returned a DIFFERENT secret than the one it stored — the caller " +
                "would open its SQLCipher database with a passphrase that was never used to " +
                "encrypt it, and the real one is gone",
        )

        restored.ksafe.close()
    }

    @Test
    fun theExemptedPrefixesAreTheSlotNamesGetOrCreateSecretActuallyWrites() = runBlocking {
        // The sweep exemption matches on these prefixes; if they ever stop naming the real slots
        // the exemption goes silently inert and the secret becomes reapable again.
        val ksafe = KSafe(fileName = JvmKSafeTest.generateUniqueFileName(), baseDir = tmp, testEngine = FakeEncryption())

        ksafe.getOrCreateSecret("plain_key")
        assertNotNull(
            ksafe.getKeyInfo(KSafeSecretSlots.PLAIN_PREFIX + "plain_key"),
            "a [A-Za-z0-9_] key must occupy PLAIN_PREFIX + key",
        )

        ksafe.getOrCreateSecret("hex.key")
        val hex = "hex.key".encodeToByteArray()
            .joinToString("") { b -> (b.toInt() and 0xff).toString(16).padStart(2, '0') }
        assertNotNull(
            ksafe.getKeyInfo(KSafeSecretSlots.HEX_PREFIX + hex),
            "a special-char key must occupy HEX_PREFIX + hex(utf8(key))",
        )

        ksafe.close()
    }
}
