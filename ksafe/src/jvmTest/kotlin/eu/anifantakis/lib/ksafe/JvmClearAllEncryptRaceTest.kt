package eu.anifantakis.lib.ksafe

import eu.anifantakis.lib.ksafe.internal.JvmSoftwareEncryption
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVault
import eu.anifantakis.lib.ksafe.internal.keyvault.JvmKeyVaultProvider
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull

/**
 * A `clearAll()` promises cryptographic erasure: destroy the key and every pre-wipe copy of the
 * ciphertext is dead. The one window where that promise used to bend is an encrypt in flight
 * across the wipe — the key was resolved, the wipe landed, and the repair re-persisted the key it
 * had just used, resurrecting exactly the material `clearAll()` erased. A pre-wipe backup of the
 * store file became decryptable again.
 *
 * These tests force that interleaving deterministically: a vault whose `get` fires the sibling
 * `clearAll` (epoch bump + record wipe) after handing out the old key — the resolution has the
 * pre-wipe key in hand while its record is already gone. The raced write must stay readable
 * (that guarantee is why the repair existed), but under a FRESH key: the wiped one stays dead.
 */
class JvmClearAllEncryptRaceTest {

    /** Map-backed [JvmKeyVault] whose [get] can fire a hook after reading — the wipe landing
     *  between key resolution and the encrypt path's epoch re-check. */
    private class RacingVault : JvmKeyVault {
        val records = ConcurrentHashMap<String, ByteArray>()
        var onGet: ((String) -> Unit)? = null

        override val name = "racing-test-vault"
        override val isOsBacked = false

        override fun get(alias: String): ByteArray? {
            val bytes = records[alias]?.copyOf()
            onGet?.invoke(alias)
            return bytes
        }

        override fun put(alias: String, keyBytes: ByteArray) {
            records[alias] = keyBytes.copyOf()
        }

        override fun delete(alias: String) {
            records.remove(alias)
        }
    }

    private fun engineOver(vault: RacingVault) = JvmSoftwareEncryption(
        KSafeConfig(),
        vaultProvider = JvmKeyVaultProvider(forced = vault, legacyOverride = vault),
    )

    @Test
    fun clearAllLandingMidEncrypt_mintsFreshKey_insteadOfResurrectingTheWipedOne() {
        val vault = RacingVault()
        val alias = "master"

        // A value written before the wipe — the copy an attacker's backup of the store would hold.
        val minter = engineOver(vault)
        val preWipeCiphertext = minter.encrypt(
            alias, "secret before wipe".encodeToByteArray(),
            hardwareIsolated = false, requireUnlockedDevice = false, aad = null,
        )
        val preWipeKey = assertNotNull(vault.records[alias]).copyOf()

        // A separate engine (cold cache) so the raced encrypt resolves through the vault, where
        // the hook lands the sibling clearAll mid-flight: old key handed out, record wiped,
        // epoch bumped — before the encrypt's own consistency re-check runs.
        val engine = engineOver(vault)
        var armed = true
        vault.onGet = { got ->
            if (armed && got == alias) {
                armed = false
                engine.onStoreCleared()
                vault.records.remove(alias)
            }
        }
        val acknowledged = "acknowledged write".encodeToByteArray()
        val racedCiphertext = engine.encrypt(
            alias, acknowledged,
            hardwareIsolated = false, requireUnlockedDevice = false, aad = null,
        )
        vault.onGet = null

        // The wiped key must stay dead: not re-persisted, and unable to open pre-wipe ciphertext.
        val persistedAfter = assertNotNull(
            vault.records[alias],
            "the raced write must leave a persisted key — its ciphertext must survive a relaunch",
        )
        assertFalse(
            persistedAfter.contentEquals(preWipeKey),
            "the key clearAll() destroyed must not be re-persisted by an in-flight encrypt — " +
                "that resurrection makes a pre-wipe backup of the store decryptable again",
        )
        assertFails("pre-wipe ciphertext must stay dead after the wipe") {
            engine.decrypt(alias, preWipeCiphertext, requireUnlockedDevice = false, aad = null)
        }

        // The half the old repair existed for must still hold: the acknowledged write is
        // readable, including from a cold engine that can only see the persisted key.
        assertContentEquals(
            acknowledged,
            engine.decrypt(alias, racedCiphertext, requireUnlockedDevice = false, aad = null),
            "the raced write must decrypt on the engine that produced it",
        )
        assertContentEquals(
            acknowledged,
            engineOver(vault).decrypt(alias, racedCiphertext, requireUnlockedDevice = false, aad = null),
            "the raced write must decrypt after a relaunch, from the persisted key alone",
        )
    }
}
