package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.DataStoreJsonStorage
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
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
import java.io.File
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Locks in: with an appNamespace, clearAll() stays a wipe across restarts. The un-namespaced
 * fallback cohort (ciphertext + plaintext key map) is carried into the namespace subdir ONCE;
 * it must not be re-imported and re-drained into the freshly wiped store on the next launch.
 */
@OptIn(ExperimentalEncodingApi::class)
class JvmNamespaceClearAllTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_nsclr_${System.nanoTime()}")
        .apply { mkdirs() }

    @AfterTest
    fun tearDown() {
        tmp.deleteRecursively()
    }

    private val fileName = "nsclr"
    private val base = "eu_anifantakis_ksafe_datastore_$fileName"
    private val namespace = "acme"

    /** Seeds an UN-namespaced JSON-fallback cohort in [tmp] as the no-Unsafe path would write it. */
    private fun seedUnNamespacedFallback(userKey: String, value: String) {
        val jsonFile = File(tmp, "$base.ksafe.json")
        val keysFile = File(tmp, "$base.ksafe-keys.json")
        val seedScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        runBlocking {
            val storage = DataStoreJsonStorage(jsonFile, seedScope)
            val engine = JvmSoftwareEncryption(
                config = KSafeConfig(),
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFile)),
            )
            // Encrypted values are JSON-encoded before encryption: a String carries its quotes.
            val ct = engine.encryptSuspend("$fileName:__ksafe_master__", "\"$value\"".encodeToByteArray())
            storage.applyBatch(
                listOf(
                    StorageOp.Put(KeySafeMetadataManager.valueRawKey(userKey), StoredValue.Text(Base64.encode(ct))),
                    StorageOp.Put(
                        KeySafeMetadataManager.metadataRawKey(userKey),
                        StoredValue.Text(KeySafeMetadataManager.buildMetadataJson(KSafeProtection.DEFAULT, accessPolicy = null)),
                    ),
                )
            )
            seedScope.coroutineContext[Job]!!.cancelAndJoin()
        }
    }

    private fun open(): KSafe = KSafe(fileName = fileName, baseDir = tmp, config = KSafeConfig(appNamespace = namespace))

    @Test
    fun clearAll_isNotUndoneByTheNextLaunch_whenAnAppNamespaceIsSet() {
        seedUnNamespacedFallback("token", "secret-token")

        val first = open()
        try {
            runBlocking {
                assertEquals("secret-token", first.get("token", ""), "precondition: the fallback cohort migrated into the namespace")
                first.clearAll()
            }
        } finally {
            first.close()
        }

        val second = open()
        try {
            runBlocking {
                assertEquals(
                    "", second.get("token", ""),
                    "a restart after clearAll() must not re-import and re-drain the un-namespaced fallback cohort",
                )
            }
        } finally {
            second.close()
        }

        val nsDir = File(tmp, namespace)
        assertTrue(
            File(nsDir, base + NAMESPACE_IMPORT_MARKER_SUFFIX).exists(),
            "the one-shot import marker must survive clearAll()'s residue sweep",
        )
        val reimported = nsDir.listFiles().orEmpty().map { it.name }
            .filter { it == "$base.ksafe.json" || it == "$base.ksafe-keys.json" || it.endsWith(".migrated") }
        assertTrue(reimported.isEmpty(), "no fallback ciphertext / key map may reappear in the namespace dir after clearAll(): $reimported")
    }
}
