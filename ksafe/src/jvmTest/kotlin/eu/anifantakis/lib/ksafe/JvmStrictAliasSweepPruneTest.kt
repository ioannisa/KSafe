package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.KSafeCore
import eu.anifantakis.lib.ksafe.internal.KSafePlatformStorage
import eu.anifantakis.lib.ksafe.internal.KSafeReservedKeys
import eu.anifantakis.lib.ksafe.internal.KeySafeMetadataManager
import eu.anifantakis.lib.ksafe.internal.StorageOp
import eu.anifantakis.lib.ksafe.internal.StoredValue
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.runBlocking
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Locks in: the delete/clearAll sweep still reaches an entry whose key lives under the strict
 * alias variant, even on a store whose write path can no longer mint one.
 *
 * The prune asks `modeTransformer` what a new USER write can carry — on web, never strict. But
 * rotation does not go through the transformer: it takes the unlock policy from the entry's own
 * metadata, so a store written before that veto rotates into exactly the key the prune would
 * then refuse to sweep, and the key outlives the data it protected.
 */
class JvmStrictAliasSweepPruneTest {

    private val cores = mutableListOf<KSafeCore>()

    @AfterTest
    fun tearDown() {
        cores.forEach { it.cancel() }
        cores.clear()
    }

    private class MemoryStorage : KSafePlatformStorage {
        private val state = MutableStateFlow<Map<String, StoredValue>>(emptyMap())
        override suspend fun snapshot(): Map<String, StoredValue> = state.value
        override fun snapshotFlow(): Flow<Map<String, StoredValue>> = state
        override suspend fun applyBatch(ops: List<StorageOp>) {
            state.update { cur ->
                val m = cur.toMutableMap()
                for (op in ops) when (op) {
                    is StorageOp.Put -> m[op.rawKey] = op.value
                    is StorageOp.Delete -> m.remove(op.rawKey)
                }
                m
            }
        }
        override suspend fun clear() { state.value = emptyMap() }
        fun seed(vararg pairs: Pair<String, StoredValue>) { state.update { it + pairs } }
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun clearAll_reapsAStrictKey_evenWhereNoNewWriteCouldMintOne() = runBlocking {
        val storage = MemoryStorage()
        val engine = StatefulFakeEncryption()

        // The entry a pre-veto release left behind, then rotation carried to generation 2 under
        // the strict alias. Its key is live and its ciphertext decrypts, so the startup orphan
        // sweep leaves it alone and the deletion below is the only thing that can reap the key.
        val strictAlias = KSafeCore.strictPerEntryAliasWithGeneration(
            baseAlias = "p.token", generation = 2, keyNamespace = null, userKey = "token",
        )
        val ciphertext = engine.encrypt(
            strictAlias, "\"secret\"".encodeToByteArray(),
            hardwareIsolated = true, requireUnlockedDevice = true, aad = null,
        )
        storage.seed(
            KeySafeMetadataManager.valueRawKey("token") to StoredValue.Text(Base64.encode(ciphertext)),
            KeySafeMetadataManager.metadataRawKey("token") to StoredValue.Text(
                KeySafeMetadataManager.buildMetadataJson(
                    protection = KSafeProtection.HARDWARE_ISOLATED,
                    accessPolicy = null,
                    envelopeVersion = KeySafeMetadataManager.ENVELOPE_VERSION_V2,
                    keyGeneration = 2,
                    strictAliasVariant = true,
                )
            ),
        )

        val core = KSafeCore(
            storage = storage,
            engineProvider = { engine },
            config = KSafeConfig(),
            memoryPolicy = KSafeMemoryPolicy.ENCRYPTED,
            plaintextCacheTtl = 5.seconds,
            resolveKeyStorage = { _, _, _ -> KSafeKeyStorage.SOFTWARE },
            resolveKeyLevel = { _, _, _ -> KSafeProtectionLevel.SOFTWARE },
            lazyLoad = false,
            keyAlias = { "p.$it" },
            masterAlias = { req -> if (req) "master_locked" else "master" },
            // The web shape: the platform vetoes every unlock policy a user write asks for.
            modeTransformer = { mode ->
                if (mode is KSafeWriteMode.Encrypted && mode.requireUnlockedDevice) {
                    mode.copy(requireUnlockedDevice = false)
                } else {
                    mode
                }
            },
        ).also { cores.add(it) }

        core.clearAll()

        assertTrue(
            engine.deletedKeys.any { it.contains(KSafeReservedKeys.STRICT_VARIANT) },
            "the entry's own metadata says its key is under the strict alias — a prune derived " +
                "from what a NEW write could carry must not exempt it from the sweep. " +
                "Deleted: ${engine.deletedKeys}",
        )
    }
}
