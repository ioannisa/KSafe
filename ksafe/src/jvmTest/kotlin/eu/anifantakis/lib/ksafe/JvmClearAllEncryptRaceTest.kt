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
 * Locks in: a `clearAll()` landing mid-encrypt must not re-persist the key it just erased, since
 * that resurrection makes a pre-wipe backup of the store decryptable again. The vault below fires
 * the sibling wipe from inside `get`, so the resolution holds the old key while its record is
 * already gone; the raced write must still be readable, but under a fresh key.
 */
class JvmClearAllEncryptRaceTest {

    /** Map-backed [JvmKeyVault] whose [get] fires a hook after reading, landing the wipe between
     *  key resolution and the encrypt path's epoch re-check. */
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

        // The pre-wipe value, standing in for the copy a stolen backup of the store would hold.
        val minter = engineOver(vault)
        val preWipeCiphertext = minter.encrypt(
            alias, "secret before wipe".encodeToByteArray(),
            hardwareIsolated = false, requireUnlockedDevice = false, aad = null,
        )
        val preWipeKey = assertNotNull(vault.records[alias]).copyOf()

        // A separate engine has a cold cache, so the raced encrypt resolves through the vault and
        // the hook can land the wipe before the encrypt's own consistency re-check runs.
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

        // The guarantee the old repair existed for still holds: an acknowledged write stays
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
