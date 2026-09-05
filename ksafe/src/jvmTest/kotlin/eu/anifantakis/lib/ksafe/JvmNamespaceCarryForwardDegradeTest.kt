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
 * Locks in: a namespace carry-forward that FAILS never promotes the empty namespace directory
 * to authoritative. The session runs from the source directory it could not copy out of, so the
 * un-namespaced values stay readable and this session's writes land where the next launch's
 * retry will pick them up — instead of creating a namespaced store file that the retry then
 * skips forever (its destination name exists) while publishing the rest of the cohort.
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
    fun failedCarryForward_runsThisSessionFromTheSourceDirectory() {
        val fileName = "nsdeg_a_${System.nanoTime()}"
        val base = base(fileName)
        seedUnNamespaced(fileName, "seeded", "v-seed")

        val log = capturingStdErr {
            withCopyFault {
                val degraded = open(fileName)
                try {
                    assertEquals(
                        "v-seed", degraded.getDirect("seeded", ""),
                        "a failed carry-forward must keep reading the store it could not copy out of",
                    )
                    runBlocking { degraded.put("sessionA", "v-a", KSafeWriteMode.Plain) }
                } finally {
                    degraded.close()
                }
            }
        }

        assertFalse(
            File(nsDir(), "$base$DATASTORE_FILE_SUFFIX").exists(),
            "a failed carry-forward must not create a namespaced store file the retry would then skip",
        )
        assertFalse(
            File(nsDir(), base + NAMESPACE_IMPORT_MARKER_SUFFIX).exists(),
            "a failed carry-forward must leave no import marker",
        )
        assertTrue(
            File(tmp, "$base$DATASTORE_FILE_SUFFIX").exists(),
            "the session's writes must land in the source store",
        )
        assertTrue(
            log.contains("carry-forward", ignoreCase = true),
            "the degrade must be reported; stderr was: $log",
        )
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
                File(nsDir(), "$base$DATASTORE_FILE_SUFFIX").exists(),
                "a later construction must join the degrade, not snapshot a store the first one is writing",
            )
            assertFalse(
                File(nsDir(), base + NAMESPACE_IMPORT_MARKER_SUFFIX).exists(),
                "a later construction must not publish the marker that would strand the first one's writes",
            )
            runBlocking { first.put("fromFirst", "v-1", KSafeWriteMode.Plain) }
            awaitValue(second, "fromFirst", "v-1")
        } finally {
            second.close()
            first.close()
        }

        val third = open(fileName)
        try {
            assertFalse(
                File(nsDir(), "$base$DATASTORE_FILE_SUFFIX").exists(),
                "the memo outlives the instances that caused it: a fresh construction still follows it",
            )
            assertEquals("v-1", third.getDirect("fromFirst", ""))
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
        // Positive control for the degrade test below, which can only assert an absence: this is
        // the same await, on a store that carried nothing forward, showing the birth-stamp does
        // arrive within it and is detectable. A store file alone is not the signal — opening a
        // store creates one under any policy — so the assertions key on the stamp itself.
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
    fun retryAfterAFailedCarryForward_importsTheWholeCohortIncludingTheSessionsWrites() {
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
            assertEquals("v-seed", retried.getDirect("seeded", ""), "the seeded value must carry forward")
            assertEquals(
                "v-a", retried.getDirect("sessionA", ""),
                "the degraded session's write must carry forward too",
            )
        } finally {
            retried.close()
        }

        assertTrue(
            File(nsDir(), base + NAMESPACE_IMPORT_MARKER_SUFFIX).exists(),
            "the successful retry must leave the one-shot marker",
        )
        assertTrue(
            File(nsDir(), "$base$DATASTORE_FILE_SUFFIX").exists(),
            "the successful retry must publish the store file",
        )
    }

    @Test
    fun failedCarryForward_degradesTheSameWayUnderAMaxAgeRotationPolicy() {
        // MaxAge birth-stamps the generation at startup with no user write, so the store file is
        // created in whichever directory this session decided to run from.
        val fileName = "nsdeg_c_${System.nanoTime()}"
        val base = base(fileName)
        val rotation = KSafeKeyRotationPolicy.MaxAge(30.milliseconds)
        seedUnNamespaced(fileName, "seeded", "v-seed")

        withCopyFault {
            val degraded = open(fileName, rotation)
            try {
                assertEquals("v-seed", degraded.getDirect("seeded", ""))
                awaitTrue("the startup birth-stamp must land in the store this session runs from") {
                    holdsTheBirthStamp(File(tmp, "$base$DATASTORE_FILE_SUFFIX"))
                }
            } finally {
                degraded.close()
            }
        }

        assertFalse(
            File(nsDir(), "$base$DATASTORE_FILE_SUFFIX").exists(),
            "the startup birth-stamp must not create the namespaced store file either",
        )

        nextLaunch()
        val retried = open(fileName, rotation)
        try {
            assertEquals("v-seed", retried.getDirect("seeded", ""), "the retry must carry the value forward")
        } finally {
            retried.close()
        }
        assertTrue(File(nsDir(), base + NAMESPACE_IMPORT_MARKER_SUFFIX).exists())
    }

    @Test
    fun failedCarryForward_doesNotReArmFallbackWinsAgainstTheSessionsNewerValue() {
        val fileName = "nsdeg_d_${System.nanoTime()}"
        val base = base(fileName)
        seedUnNamespacedFallback(fileName, "token", "old-value")

        withCopyFault {
            val degraded = open(fileName)
            try {
                runBlocking {
                    assertEquals(
                        "old-value", degraded.get("token", ""),
                        "the degraded session must drain the fallback it is sitting on",
                    )
                    degraded.put("token", "new-value")
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
                    "new-value", retried.get("token", ""),
                    "the retry must not let the stale fallback overwrite the degraded session's write",
                )
            }
        } finally {
            retried.close()
        }
        assertTrue(File(nsDir(), base + NAMESPACE_IMPORT_MARKER_SUFFIX).exists())
    }

    /** Seeds an UN-namespaced JSON-fallback cohort in [tmp] as the no-`Unsafe` path would write it. */
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
