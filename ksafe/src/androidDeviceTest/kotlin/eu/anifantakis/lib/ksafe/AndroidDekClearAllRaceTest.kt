package eu.anifantakis.lib.ksafe

import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.anifantakis.lib.ksafe.internal.AndroidKeystoreEncryption
import eu.anifantakis.lib.ksafe.internal.WrappedDekStore
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFails
import org.junit.runner.RunWith

/**
 * The Android twin of `JvmClearAllEncryptRaceTest`: a `clearAll()` racing an in-flight DEK
 * encrypt must not end with the wiped DEK re-persisted. The KEK stays in the real device
 * Keystore — only the wrapped-DEK store is replaced with one whose `load` fires the sibling
 * teardown mid-resolution, which is the interleaving the epoch fence exists to catch.
 */
@RunWith(AndroidJUnit4::class)
class AndroidDekClearAllRaceTest {

    /** Map-backed [WrappedDekStore] whose [load] can fire a hook after reading. */
    private class RacingDekStore : WrappedDekStore {
        val records = ConcurrentHashMap<String, ByteArray>()
        var onLoad: ((String) -> Unit)? = null

        override val isGenerationAware = true

        override fun load(alias: String): ByteArray? {
            val bytes = records[alias]?.copyOf()
            onLoad?.invoke(alias)
            return bytes
        }

        override fun save(alias: String, wrapped: ByteArray) {
            records[alias] = wrapped.copyOf()
        }

        override fun delete(alias: String) {
            records.remove(alias)
        }
    }

    // Unique per run so the KEK minted into the device Keystore never collides across runs.
    private val alias = "dekracetest${System.nanoTime()}"
    private val cleanupEngines = mutableListOf<AndroidKeystoreEncryption>()

    @AfterTest
    fun tearDown() {
        cleanupEngines.forEach { runCatching { it.deleteKey(alias) } }
    }

    private fun engineOver(store: RacingDekStore) =
        AndroidKeystoreEncryption(KSafeConfig(), store, useSoftwareDek = true)
            .also { cleanupEngines.add(it) }

    @Test
    fun clearAllLandingMidEncrypt_mintsFreshDek_insteadOfResurrectingTheWipedOne() {
        val store = RacingDekStore()

        // A value written before the wipe — the copy an attacker's backup of the store would hold.
        val minter = engineOver(store)
        val preWipeCiphertext = minter.encrypt(
            alias, "secret before wipe".encodeToByteArray(),
            hardwareIsolated = false, requireUnlockedDevice = false, aad = null,
        )

        // A separate engine (cold DEK cache) so the raced encrypt resolves through the store,
        // where the hook lands the sibling clearAll mid-flight: old DEK handed out, record
        // wiped, teardown epoch bumped — before the encrypt's own re-check runs.
        val engine = engineOver(store)
        var armed = true
        store.onLoad = { got ->
            if (armed && got == alias) {
                armed = false
                engine.onStoreCleared()
                store.records.remove(alias)
            }
        }
        val acknowledged = "acknowledged write".encodeToByteArray()
        val racedCiphertext = engine.encrypt(
            alias, acknowledged,
            hardwareIsolated = false, requireUnlockedDevice = false, aad = null,
        )
        store.onLoad = null

        // The wiped DEK must stay dead: pre-wipe ciphertext unreadable ever again. (The DEK
        // never leaves the engine, so death is asserted behaviourally — if the repair had
        // re-persisted it, this decrypt would succeed.)
        assertFails("pre-wipe ciphertext must stay dead after the wipe") {
            engine.decrypt(alias, preWipeCiphertext, requireUnlockedDevice = false, aad = null)
        }

        // The half the old repair existed for must still hold: the acknowledged write is
        // readable, including from a cold engine that can only see the persisted record.
        assertContentEquals(
            acknowledged,
            engine.decrypt(alias, racedCiphertext, requireUnlockedDevice = false, aad = null),
            "the raced write must decrypt on the engine that produced it",
        )
        assertContentEquals(
            acknowledged,
            engineOver(store).decrypt(alias, racedCiphertext, requireUnlockedDevice = false, aad = null),
            "the raced write must decrypt after a relaunch, from the persisted record alone",
        )
    }
}
