package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.DATASTORE_FILE_SUFFIX
import eu.anifantakis.lib.ksafe.internal.DataStoreJsonStorage
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.PrintStream
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds

/**
 * Locks in: a failed namespace carry-forward never runs the session from the un-namespaced store,
 * which every un-namespaced KSafe app of the OS user shares, so its writes and `clearAll()` cannot
 * reach another app's data. The session runs on the empty namespace directory instead, and the
 * next launch whose copy succeeds replaces what it wrote with the carried-forward store — unless
 * the session cleared the store, which must stick. The app's own older namespace directory is not
 * shared, so a session may still run from it.
 */
@OptIn(ExperimentalEncodingApi::class)
class JvmNamespaceCarryForwardDegradeTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_nsdeg_${System.nanoTime()}")
        .apply { mkdirs() }

    @AfterTest
    fun tearDown() {
        copyForwardCopyForTest = null
        clearCarryForwardDegradeMemoForTest()
        tmp.deleteRecursively()
    }

    /** The degrade memo lives until process exit, so a "next launch" must forget it. */
    private fun nextLaunch() = clearCarryForwardDegradeMemoForTest()

    private val namespace = "acme"

    private fun base(fileName: String) = "eu_anifantakis_ksafe_datastore_$fileName"

    private fun nsDir() = File(tmp, namespace)

    private fun open(
        fileName: String,
        rotation: KSafeKeyRotationPolicy = KSafeKeyRotationPolicy.Never,
    ): KSafe = KSafe(
        fileName = fileName,
        baseDir = tmp,
        config = KSafeConfig(appNamespace = namespace, keyRotationPolicy = rotation),
    )

    /** The un-namespaced store in [tmp], which every un-namespaced app of the OS user shares. */
    private fun openShared(fileName: String): KSafe = KSafe(fileName = fileName, baseDir = tmp)

    /** A literal, not the constant: the name is on disk, so renaming it strands old sessions. */
    private fun degradedMarker(base: String) = File(nsDir(), "$base.ns-degraded")

    private fun importMarker(base: String) = File(nsDir(), base + NAMESPACE_IMPORT_MARKER_SUFFIX)

    private fun readShared(fileName: String, key: String): String {
        val shared = openShared(fileName)
        try {
            return shared.getDirect(key, "")
        } finally {
            shared.close()
        }
    }

    /** An un-namespaced store as a pre-namespace release left it behind. */
    private fun seedUnNamespaced(fileName: String, key: String, value: String) {
        val seed = KSafe(fileName = fileName, baseDir = tmp)
        try {
            runBlocking { seed.put(key, value, KSafeWriteMode.Plain) }
        } finally {
            seed.close()
        }
    }

    private inline fun withCopyFault(block: () -> Unit) {
        copyForwardCopyForTest = { _, _ -> throw IOException("injected copy failure") }
        try {
            block()
        } finally {
            copyForwardCopyForTest = null
        }
    }

    private inline fun capturingStdErr(block: () -> Unit): String {
        val original = System.err
        val buffer = ByteArrayOutputStream()
        System.setErr(PrintStream(buffer, true))
        try {
            block()
        } finally {
            System.setErr(original)
        }
        return buffer.toString()
    }

    @Test
    fun failedCarryForward_neverRunsTheSessionFromTheSharedStore() {
        val fileName = "nsdeg_a_${System.nanoTime()}"
        val base = base(fileName)
        seedUnNamespaced(fileName, "seeded", "v-seed")

        val log = capturingStdErr {
            withCopyFault {
                val degraded = open(fileName)
                try {
                    assertEquals("", degraded.getDirect("seeded", ""), "the session must not read the shared store")
                    runBlocking { degraded.put("sessionA", "v-a", KSafeWriteMode.Plain) }
                } finally {
                    degraded.close()
                }
            }
        }

        assertEquals("", readShared(fileName, "sessionA"), "the session's write must not reach the shared store")
        assertEquals("v-seed", readShared(fileName, "seeded"))
        assertTrue(degradedMarker(base).exists(), "the session must be marked as temporary")
        assertFalse(importMarker(base).exists(), "a failed carry-forward must leave no import marker")
        assertTrue(log.contains("carry-forward", ignoreCase = true), "the degrade must be reported; stderr was: $log")
    }

    @Test
    fun clearAllInADegradedSession_leavesTheSharedStoreAlone() {
        val fileName = "nsdeg_g_${System.nanoTime()}"
        seedUnNamespaced(fileName, "seeded", "v-seed")

        withCopyFault {
            val degraded = open(fileName)
            try {
                runBlocking { degraded.clearAll() }
            } finally {
                degraded.close()
            }
        }

        assertEquals("v-seed", readShared(fileName, "seeded"), "another app's store must survive this session's clearAll()")
    }

    @Test
    fun clearAllInADegradedSession_isNotUndoneByTheNextLaunch() {
        val fileName = "nsdeg_h_${System.nanoTime()}"
        val base = base(fileName)
        seedUnNamespaced(fileName, "seeded", "v-seed")

        withCopyFault {
            val degraded = open(fileName)
            try {
                runBlocking { degraded.clearAll() }
            } finally {
                degraded.close()
            }
        }

        nextLaunch()
        val after = open(fileName)
        try {
            assertEquals("", after.getDirect("seeded", ""), "a wipe must stick: the next launch must not carry the store back")
        } finally {
            after.close()
        }
        assertFalse(degradedMarker(base).exists())
        assertEquals("v-seed", readShared(fileName, "seeded"), "the shared store keeps its own data")
    }

    @Test
    fun failedCarryForward_fromTheAppsOwnOlderNamespaceDir_stillRunsFromIt() {
        val fileName = "nsdeg_i_${System.nanoTime()}"
        // "acme app" sanitizes to the canonical "acme_app-<digest>"; older releases used "acme_app".
        val ownOlderDir = File(tmp, "acme_app").apply { mkdirs() }
        val seed = KSafe(fileName = fileName, baseDir = ownOlderDir)
        try {
            runBlocking { seed.put("seeded", "v-own", KSafeWriteMode.Plain) }
        } finally {
            seed.close()
        }

        withCopyFault {
            val degraded = KSafe(fileName = fileName, baseDir = tmp, config = KSafeConfig(appNamespace = "acme app"))
            try {
                assertEquals("v-own", degraded.getDirect("seeded", ""), "the app's own older directory is not shared")
            } finally {
                degraded.close()
            }
        }
        assertTrue(tmp.walkTopDown().none { it.name.endsWith(".ns-degraded") }, "nothing to mark: no temporary session ran")
    }

    @Test
    fun secondConstructionInTheSameProcess_followsTheFirstOnesDegrade() {
        val fileName = "nsdeg_e_${System.nanoTime()}"
        val base = base(fileName)
        seedUnNamespaced(fileName, "seeded", "v-seed")

        copyForwardCopyForTest = { _, _ -> throw IOException("injected copy failure") }
        val first = open(fileName)
        copyForwardCopyForTest = null

        val second = open(fileName)
        try {
            assertFalse(
                importMarker(base).exists(),
                "a later construction must join the degrade, not copy over a store the first one is using",
            )
            runBlocking { first.put("fromFirst", "v-1", KSafeWriteMode.Plain) }
            awaitValue(second, "fromFirst", "v-1")
        } finally {
            second.close()
            first.close()
        }

        val third = open(fileName)
        try {
            assertEquals("v-1", third.getDirect("fromFirst", ""), "the memo outlives the instances that caused it")
            assertFalse(importMarker(base).exists())
        } finally {
            third.close()
        }
    }

    private fun awaitTrue(message: String, timeoutMs: Long = 10_000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(25)
        }
        fail(message)
    }

    private fun awaitValue(ksafe: KSafe, key: String, expected: String) = awaitTrue(
        "'$key' never reached '$expected' through the sibling instance",
    ) { ksafe.getDirect(key, "") == expected }

    /** The generation record is stored under its raw key name, which survives verbatim in the pb. */
    private fun holdsTheBirthStamp(file: File): Boolean = file.exists() &&
        String(file.readBytes(), Charsets.ISO_8859_1).contains(KeySafeMetadataManager.KEYGEN_RAW_KEY)

    @Test
    fun maxAgeStartupBirthStamp_reachesTheStoreWithNoUserWrite() {
        // Positive control for the degrade test below, which can only assert an absence: the same
        // await, on a store that carried nothing forward. A store file alone is not the signal —
        // opening a store creates one under any policy — so the assertions key on the stamp itself.
        val stamped = "nsdeg_f1_${System.nanoTime()}"
        val stampedPb = File(nsDir(), "${base(stamped)}$DATASTORE_FILE_SUFFIX")
        val rotating = open(stamped, KSafeKeyRotationPolicy.MaxAge(30.milliseconds))
        try {
            awaitTrue("the MaxAge birth-stamp must reach the store with no user write") {
                holdsTheBirthStamp(stampedPb)
            }
        } finally {
            rotating.close()
        }

        val quiet = "nsdeg_f2_${System.nanoTime()}"
        val quietPb = File(nsDir(), "${base(quiet)}$DATASTORE_FILE_SUFFIX")
        val never = open(quiet)
        try {
            Thread.sleep(1_000)
            assertFalse(holdsTheBirthStamp(quietPb), "only a MaxAge policy stamps a generation birth")
        } finally {
            never.close()
        }
    }

    @Test
    fun nextLaunchAfterADegradedSession_restoresTheCarriedForwardStore() {
        val fileName = "nsdeg_b_${System.nanoTime()}"
        val base = base(fileName)
        seedUnNamespaced(fileName, "seeded", "v-seed")

        withCopyFault {
            val degraded = open(fileName)
            try {
                runBlocking { degraded.put("sessionA", "v-a", KSafeWriteMode.Plain) }
            } finally {
                degraded.close()
            }
        }

        nextLaunch()
        val retried = open(fileName)
        try {
            assertEquals("v-seed", retried.getDirect("seeded", ""), "the carried-forward value must come back")
            assertEquals("", retried.getDirect("sessionA", ""), "the temporary session's write is replaced")
        } finally {
            retried.close()
        }
        assertTrue(importMarker(base).exists(), "the successful retry must leave the one-shot marker")
        assertFalse(degradedMarker(base).exists(), "the temporary session is over")
    }

    @Test
    fun failedCarryForward_degradesTheSameWayUnderAMaxAgeRotationPolicy() {
        // MaxAge birth-stamps the generation at startup with no user write, so the store file is
        // created in whichever directory this session runs from.
        val fileName = "nsdeg_c_${System.nanoTime()}"
        val base = base(fileName)
        val rotation = KSafeKeyRotationPolicy.MaxAge(30.milliseconds)
        seedUnNamespaced(fileName, "seeded", "v-seed")

        withCopyFault {
            val degraded = open(fileName, rotation)
            try {
                awaitTrue("the startup birth-stamp must land in the session's own store") {
                    holdsTheBirthStamp(File(nsDir(), "$base$DATASTORE_FILE_SUFFIX"))
                }
            } finally {
                degraded.close()
            }
        }
        assertFalse(
            holdsTheBirthStamp(File(tmp, "$base$DATASTORE_FILE_SUFFIX")),
            "the startup birth-stamp must not reach the shared store",
        )

        nextLaunch()
        val retried = open(fileName, rotation)
        try {
            assertEquals("v-seed", retried.getDirect("seeded", ""), "the session's store file must not block the retry")
        } finally {
            retried.close()
        }
        assertTrue(importMarker(base).exists())
    }

    @Test
    fun nextLaunchAfterADegradedSession_carriesTheFallbackCohortForwardWhole() {
        val fileName = "nsdeg_d_${System.nanoTime()}"
        val base = base(fileName)
        seedUnNamespacedFallback(fileName, "token", "old-value")

        withCopyFault {
            val degraded = open(fileName)
            try {
                runBlocking {
                    assertEquals("", degraded.get("token", ""), "the session must not drain the shared fallback")
                    degraded.put("token", "session-value")
                }
            } finally {
                degraded.close()
            }
        }

        nextLaunch()
        val retried = open(fileName)
        try {
            runBlocking {
                assertEquals(
                    "old-value", retried.get("token", ""),
                    "the cohort must arrive whole from one source, not mixed with the session's files",
                )
            }
        } finally {
            retried.close()
        }
        assertTrue(importMarker(base).exists())
    }

    /** Seeds an un-namespaced JSON-fallback cohort in [tmp] as the no-`Unsafe` path would write it. */
    private fun seedUnNamespacedFallback(fileName: String, userKey: String, value: String) {
        val base = base(fileName)
        val jsonFile = File(tmp, "$base.ksafe.json")
        val keysFile = File(tmp, "$base.ksafe-keys.json")
        val seedScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        runBlocking {
            val storage = DataStoreJsonStorage(jsonFile, seedScope)
            val engine = JvmSoftwareEncryption(
                config = KSafeConfig(),
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
            )
            val ct = engine.encryptSuspend("$fileName:__ksafe_master__", "\"$value\"".encodeToByteArray())
            storage.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey(userKey), StoredValue.Text(Base64.encode(ct))),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey(userKey),
                        StoredValue.Text(
                            KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)
                        ),
                    ),
                )
            )
            seedScope.coroutineContext[Job]!!.cancelAndJoin()
        }
    }
}
