package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.AppleKeychainEncryption
import eu.anifantakis.lib.ksafe.internal.KSafeAliasFormat
import eu.anifantakis.lib.ksafe.internal.KSafeEncryption
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.SecurityChecker
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import eu.anifantakis.lib.ksafe.internal.cleanupOrphanedKeychainEntries
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Locks in, against the REAL Keychain and Secure Enclave, that a sweep over a store which
 * vouches for no encrypted entry destroys no key material: such a store is a partial view (failed
 * migration, quarantined file, a restore that recovered the Keychain but not the store), and the
 * keys it would reap cannot be recreated.
 *
 * The sweep is driven directly, as the macOS no-op test does, rather than through the `KSafe`
 * factory: the reaping path only exists for the DEFAULT store, and reaching it through the factory
 * would mean wiping the default DataStore file out from under the rest of the suite.
 *
 * Two environments weaken this today, and it asserts the property in both rather than the guard:
 * the Simulator has no reachable Keychain (the engine serves keys from a sandbox file store, so
 * the scans see nothing), and on a real device the scans DO return items but their attribute
 * lookup yields null for every one, so classification currently produces no candidates at all.
 * It begins discriminating the guard as soon as that lookup returns accounts again.
 */
@OptIn(ExperimentalUuidApi::class)
class IosKeychainOrphanSweepGuardTest {

    private val service = "eu.anifantakis.ksafe"
    private val masters = setOf(KSafeReservedKeys.MASTER, KSafeReservedKeys.MASTER_LOCKED)

    /** A frozen store view; the sweep only ever reads it. */
    private class SnapshotStorage(private val map: Map<String, StoredValue>) : KSafePlatformStorage {
        override suspend fun snapshot(): Map<String, StoredValue> = map
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = flowOf(map)
        override suspend fun applyBatch(ops: List<StorageOp>) {}
        override suspend fun clear() {}
    }

    /**
     * The real engine, except that a delete is only CARRIED OUT for this test's own alias. The
     * root sweep classifies every unrecognised account under the service, so an unrestricted run
     * on a real device could reap the rest of the suite's live keys; the recorded list still shows
     * exactly what the sweep decided to destroy.
     */
    private class ScopedDeleteEngine(
        private val real: KSafeEncryption,
        private val ownAliases: Set<String>,
    ) : KSafeEncryption {
        val requestedDeletes = mutableListOf<String>()

        override fun encrypt(
            identifier: String,
            data: ByteArray,
            hardwareIsolated: Boolean,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray = real.encrypt(identifier, data, hardwareIsolated, requireUnlockedDevice, aad)

        override fun decrypt(
            identifier: String,
            data: ByteArray,
            requireUnlockedDevice: Boolean?,
            aad: ByteArray?,
        ): ByteArray = real.decrypt(identifier, data, requireUnlockedDevice, aad)

        override fun deleteKey(identifier: String) {
            requestedDeletes += identifier
            if (identifier in ownAliases) real.deleteKey(identifier)
        }
    }

    /** Probe ids carry no dot, so the root sweep treats them as its own bare key ids. */
    private fun probeKey(): String =
        "ksafeSweepProbe" + Uuid.random().toString().filter { it in 'a'..'f' || it in '0'..'9' }.take(12)

    @Test
    fun secureEnclaveKeySurvivesASweepOverAStoreThatVouchesForNothing() = runBlocking {
        // The Simulator's sandboxed test process has no reachable Keychain at all (key reads fail
        // errSecNotAvailable, which is not the entitlement error the sandbox fallback engages on),
        // so there is nothing here to mint, scan, or preserve.
        if (SecurityChecker.isEmulator()) {
            println("KSafe test: no Keychain on the Simulator — sweep unexercised.")
            return@runBlocking
        }
        val real = AppleKeychainEncryption(serviceName = service)
        val alias = KSafeAliasFormat.dotted(null, probeKey())
        val plaintext = "device-secret".encodeToByteArray()
        val ciphertext = real.encrypt(alias, plaintext, hardwareIsolated = true)
        try {
            assertContentEquals(plaintext, real.decrypt(alias, ciphertext), "precondition: the key is live")

            // The whole store is one reserved rotation-state record: the encrypted entries it
            // once had are gone, so it vouches for nothing and its keys are not orphans.
            val scoped = ScopedDeleteEngine(real, setOf(alias))
            cleanupOrphanedKeychainEntries(
                storage = SnapshotStorage(
                    mapOf(KeySafeMetadataManager.KEYGEN_RAW_KEY to StoredValue.Text("{\"g\":2}"))
                ),
                engine = scoped,
                serviceName = service,
                fileName = null,
                legacyEncryptedPrefix = KeySafeMetadataManager.LEGACY_ENCRYPTED_PREFIX,
                seKeyTagPrefix = AppleKeychainEncryption.SE_KEY_TAG_PREFIX,
                reservedKeyIds = masters,
            )

            assertFalse(
                alias in scoped.requestedDeletes,
                "the sweep decided to destroy a live Secure Enclave key over a store that " +
                    "vouches for no entry; deletes requested: ${scoped.requestedDeletes}",
            )
            assertContentEquals(
                plaintext,
                real.decrypt(alias, ciphertext),
                "the Secure Enclave key must still decrypt after the sweep",
            )
        } finally {
            real.deleteKey(alias)
        }
    }
}
