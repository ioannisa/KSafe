package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.DataStoreJsonStorage
import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.keyvault.FileKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import eu.anifantakis.lib.ksafe.internal.migrateJsonFallbackToOsBacked
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
 * Forward half of the alias-derivation lockstep, for the one consumer commonTest cannot reach:
 * `JvmFallbackMigration` lives in jvmMain. (The common halves — metadata round-trip and the
 * backward parse — are in `KSafeAliasDerivationLockstepTest`.)
 *
 * The migration decrypts every fallback entry under an alias it derives from the entry's RECORDED
 * metadata. A derivation that differs from the core's by one byte does not fail loudly: the
 * decrypt fails, the entry counts as a permanent skip, the fallback file is archived anyway, and
 * the entry is GONE from the live store. This copy drifted from the shared formula twice — first
 * missing the `sa` strict-variant marker, then missing the unknown-envelope gate — so the whole
 * metadata matrix is driven through the real migration here rather than sampled.
 *
 * Method: seed each row's ciphertext under the alias/AAD `KSafeCore` derives, run the real
 * migration, and require that every row landed and still decrypts under that same alias/AAD. The
 * target engine also records the identifiers it was asked to encrypt under, so a mismatch names
 * the alias instead of only reporting a missing entry.
 */
@OptIn(ExperimentalEncodingApi::class)
class JvmFallbackMigrationAliasLockstepTest {

    private val tmp = File(System.getProperty("java.io.tmpdir"), "ksafe_lockstep_${System.nanoTime()}")
        .apply { mkdirs() }

    private val scopes = mutableListOf<CoroutineScope>()

    private fun newScope(): CoroutineScope =
        CoroutineScope(Dispatchers.IO + SupervisorJob()).also { scopes += it }

    @AfterTest
    fun tearDown() {
        runBlocking { scopes.forEach { it.coroutineContext[Job]?.cancelAndJoin() } }
        tmp.deleteRecursively()
    }

    // A NAMED store: keyNamespace feeds the rotated/strict fingerprint, and passing it wrong is
    // one of the ways this copy can silently diverge.
    private val fileName = "vault"
    private val keyNamespace: String? = fileName
    private val storeIdentity = "~/ksafe/vault"
    private val keyAlias: (String) -> String = { KSafeAliasFormat.colon(fileName, it) }
    private val masterAlias: (Boolean) -> String = { unlocked ->
        KSafeAliasFormat.colon(
            fileName,
            if (unlocked) KSafeReservedKeys.MASTER_LOCKED else KSafeReservedKeys.MASTER,
        )
    }

    private data class Row(
        val userKey: String,
        val envelopeVersion: Int,
        val protection: KSafeProtection,
        val strict: Boolean,
        val unlocked: Boolean,
        val generation: Int,
    ) {
        val plaintext: String get() = "secret|$userKey"
    }

    private fun matrix(): List<Row> {
        val rows = mutableListOf<Row>()
        var n = 0
        for (envelopeVersion in listOf(
            KeySafeMetadataManager.ENVELOPE_VERSION_V1,
            KeySafeMetadataManager.ENVELOPE_VERSION_V2,
            KeySafeMetadataManager.ENVELOPE_VERSION_V3,
        )) {
            for (protection in listOf(KSafeProtection.DEFAULT, KSafeProtection.HARDWARE_ISOLATED)) {
                for (strict in listOf(false, true)) {
                    for (unlocked in listOf(false, true)) {
                        for (generation in 1..3) {
                            rows += Row("k${n++}", envelopeVersion, protection, strict, unlocked, generation)
                        }
                    }
                }
            }
        }
        return rows
    }

    private fun expectedAlias(row: Row): String = KSafeCore.aliasForRecordedMeta(
        userKey = row.userKey,
        protection = row.protection,
        envelopeVersion = row.envelopeVersion,
        requireUnlockedDevice = row.unlocked,
        keyGeneration = row.generation,
        strictAliasVariant = row.strict,
        masterAlias = masterAlias,
        keyAlias = keyAlias,
        keyNamespace = keyNamespace,
    )

    private fun expectedAad(row: Row): ByteArray? = KSafeCore.aadForEnvelope(
        storeIdentity, row.userKey, row.protection, row.unlocked, row.generation, row.envelopeVersion,
    )

    private fun metadata(row: Row): String = KeySafeMetadataManager.buildMetadataJson(
        protection = row.protection,
        accessPolicy = KeySafeMetadataManager.accessPolicyFor(row.unlocked),
        envelopeVersion = row.envelopeVersion,
        keyGeneration = row.generation,
        strictAliasVariant = row.strict,
    )

    /** Delegates to a real engine so decrypts still work, and records what it was asked to encrypt. */
    private class RecordingEngine(private val delegate: KSafeEncryption) : KSafeEncryption {
        val encryptedUnder = mutableListOf<String>()
        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray {
            encryptedUnder += identifier
            return delegate.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)
        }
        override fun decrypt(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray = delegate.decrypt(identifier, data, requireUnlockedDevice, aad)
        override fun deleteKey(identifier: String) = delegate.deleteKey(identifier)
    }

    /** The user key of the row whose envelope this build cannot know how to decrypt. */
    private val futureEnvelopeKey = "fromTheFuture"
    private val futureEnvelopeCiphertext = "bm90LW91cnMtdG8tdG91Y2g="

    @Test
    fun everyRecordedMetadataShape_migratesUnderTheAliasTheCoreDerives() {
        val rows = matrix()
        val jsonFallback = File(tmp, "lockstep.ksafe.json")
        val keysFallback = File(tmp, "lockstep.ksafe-keys.json")
        val config = KSafeConfig()

        // Seed the fallback: each row's ciphertext minted under the alias + AAD the CORE derives
        // for that recorded metadata. If the migration derives anything else, its decrypt fails.
        val srcScope = newScope()
        runBlocking {
            val srcStorage = DataStoreJsonStorage(jsonFallback, srcScope)
            val srcEngine = JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(legacyOverride = FileKeyVault(keysFallback)),
            )
            val ops = mutableListOf<StorageOp>()
            for (row in rows) {
                val cipher = srcEngine.encryptSuspend(
                    identifier = expectedAlias(row),
                    data = row.plaintext.encodeToByteArray(),
                    hardwareIsolated = row.protection == KSafeProtection.HARDWARE_ISOLATED,
                    requireUnlockedDevice = row.unlocked,
                    aad = expectedAad(row),
                )
                ops += StorageOp.Put(
                    KeySafeMetadataManager.valueRawKey(row.userKey),
                    StoredValue.Text(Base64.encode(cipher)),
                )
                ops += StorageOp.Put(
                    KeySafeMetadataManager.metadataRawKey(row.userKey),
                    StoredValue.Text(metadata(row)),
                )
            }
            // An envelope from a newer KSafe: the migration must NOT probe it as a known version
            // (a failed probe is a permanent skip, and permanent skips do not block archiving, so
            // the entry would vanish into the .migrated file). It must be carried verbatim.
            ops += StorageOp.Put(
                KeySafeMetadataManager.valueRawKey(futureEnvelopeKey),
                StoredValue.Text(futureEnvelopeCiphertext),
            )
            ops += StorageOp.Put(
                KeySafeMetadataManager.metadataRawKey(futureEnvelopeKey),
                StoredValue.Text(
                    KeySafeMetadataManager.buildMetadataJson(
                        protection = KSafeProtection.DEFAULT,
                        accessPolicy = null,
                        envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_MAX_KNOWN + 1,
                    )
                ),
            )
            srcStorage.applyBatch(ops)
        }
        runBlocking { srcScope.coroutineContext[Job]!!.cancelAndJoin() } // release the DataStore handle

        val targetScope = newScope()
        val target = DataStoreJsonStorage(File(tmp, "lockstep-target.json"), targetScope)
        val targetEngine = RecordingEngine(
            JvmSoftwareEncryption(
                config = config,
                vaultProvider = JvmKeyVaultProvider(
                    legacyOverride = FileKeyVault(File(tmp, "lockstep-target-keys.json")),
                ),
            )
        )

        migrateJsonFallbackToOsBacked(
            config = config,
            jsonFallback = jsonFallback,
            keysFallback = keysFallback,
            target = target,
            targetEngine = targetEngine,
            keyAlias = keyAlias,
            masterAlias = masterAlias,
            storeIdentity = storeIdentity,
            keyNamespace = keyNamespace,
        )

        runBlocking {
            val snapshot = target.snapshot()
            val missing = mutableListOf<String>()
            for (row in rows) {
                val cipher =
                    (snapshot[KeySafeMetadataManager.valueRawKey(row.userKey)] as? StoredValue.Text)?.value
                if (cipher == null) {
                    missing += "${row.userKey} $row"
                    continue
                }
                assertEquals(
                    row.plaintext,
                    targetEngine.decrypt(
                        expectedAlias(row), Base64.decode(cipher), row.unlocked, expectedAad(row),
                    ).decodeToString(),
                    "the migrated entry for $row must still decrypt under the alias + AAD the " +
                        "core derives — the migration re-encrypted it under a different one",
                )
                assertEquals(
                    metadata(row),
                    (snapshot[KeySafeMetadataManager.metadataRawKey(row.userKey)] as StoredValue.Text).value,
                    "the migration must carry the recorded metadata verbatim for $row",
                )
            }
            assertTrue(
                missing.isEmpty(),
                "the migration DROPPED ${missing.size} of ${rows.size} rows — its alias " +
                    "derivation diverged from KSafeCore's, the decrypt failed, and the entries " +
                    "were archived out of the live store:\n" + missing.joinToString("\n"),
            )

            // The future-envelope entry: carried through byte-for-byte, never re-encrypted.
            assertEquals(
                futureEnvelopeCiphertext,
                (snapshot[KeySafeMetadataManager.valueRawKey(futureEnvelopeKey)] as? StoredValue.Text)?.value,
                "an entry whose envelope version this build does not know must be carried " +
                    "verbatim, not probed, skipped and archived away",
            )

            // The recorded encrypt identifiers are the aliases the migration actually derived.
            assertEquals(
                rows.map { expectedAlias(it) }.toSet(),
                targetEngine.encryptedUnder.toSet(),
                "the set of aliases the migration re-encrypted under must equal the set " +
                    "KSafeCore derives for the same recorded metadata",
            )
            // Exactly one re-encrypt per matrix row and none for the future-envelope entry. (Its
            // alias cannot be checked by name: a DEFAULT entry rides the shared master alias, so
            // the name is not unique to it — the call COUNT is what distinguishes it.)
            assertEquals(
                rows.size, targetEngine.encryptedUnder.size,
                "the migration must re-encrypt each of the ${rows.size} known-envelope rows exactly " +
                    "once and never touch the future-envelope entry",
            )
            targetScope.coroutineContext[Job]!!.cancelAndJoin()
        }
    }

    @Test
    fun aliasDerivationIsSharedWithTheCore_notReDerivedInTheMigration() {
        // The matrix above proves lockstep behaviourally; this states the structural reason it
        // holds, so a future re-derivation in JvmFallbackMigration has to break something visible
        // rather than merely drifting. Every row's alias must come out of the core's producers.
        for (row in matrix()) {
            val fromCore = expectedAlias(row)
            val expected = when {
                row.envelopeVersion >= KeySafeMetadataManager.ENVELOPE_VERSION_V2 &&
                    row.protection == KSafeProtection.DEFAULT ->
                    KSafeCore.aliasWithGeneration(masterAlias(row.unlocked), row.generation)
                row.strict -> KSafeCore.strictPerEntryAliasWithGeneration(
                    keyAlias(row.userKey), row.generation, keyNamespace, row.userKey,
                )
                else -> KSafeCore.perEntryAliasWithGeneration(
                    keyAlias(row.userKey), row.generation, keyNamespace, row.userKey,
                )
            }
            assertEquals(expected, fromCore, "routing branch changed for $row")
        }
    }
}
