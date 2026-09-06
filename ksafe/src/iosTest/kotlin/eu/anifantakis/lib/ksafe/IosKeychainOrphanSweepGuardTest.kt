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
 * Locks in, against the real Keychain and Secure Enclave, that a sweep over a store vouching for no
 * encrypted entry destroys no key material: such a store is a partial view (failed migration,
 * quarantined file, half-restored backup), and the keys it would reap cannot be recreated. Both
 * environments are inert today — no Keychain on the Simulator, null attribute lookups on device.
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
     * The real engine, except that deletes are only carried out for this test's own alias — the
     * root sweep classifies every unrecognised account under the service, so an unrestricted run
     * on a device would reap the rest of the suite's live keys.
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
        // The Simulator's sandboxed test process has no reachable Keychain: reads fail
        // errSecNotAvailable, not the entitlement error the sandbox fallback engages on.
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

            // Driven directly rather than through the KSafe factory: reaping only runs for the
            // default store, and the factory route would wipe the default DataStore file out from
            // under the rest of the suite. This store is one reserved record — it vouches for none.
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
