package eu.anifantakis.lib.ksafe.internal.keyvault

import eu.anifantakis.lib.ksafe.encodeBase64
import eu.anifantakis.lib.ksafe.decodeBase64
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import com.sun.jna.platform.win32.Crypt32Util

/**
 * Windows key vault using DPAPI via JNA's [Crypt32Util]: the key is wrapped under the current user's
 * login credentials. Defeats offline disk theft, not code running as the same user.
 */
internal class WindowsDpapiKeyVault(
    dataStore: DataStore<Preferences>,
    /** Folded into the on-disk key prefix (`ksafe_dpapi_<ns>_`); blank = the un-namespaced prefix. */
    appNamespace: String = "",
) : JvmKeyVault {

    private val store = DataStorePrefStore(
        dataStore,
        if (appNamespace.isBlank()) BLOB_PREFIX else "$BLOB_PREFIX${appNamespace}_",
    )

    override val name: String = "Windows DPAPI (CryptProtectData, current-user)"
    override val isOsBacked: Boolean = true

    override fun get(alias: String): ByteArray? {
        val wrapped = store.getString(alias) ?: return null
        // A blob that can no longer be unprotected is not a miss — throw "unavailable" so the
        // sweep leaves the ciphertext intact and writes fail closed instead of minting a new key.
        return try {
            Crypt32Util.cryptUnprotectData(decodeBase64(wrapped))
        } catch (e: Throwable) {
            throw vaultUnavailable(
                alias,
                "Windows DPAPI could not unprotect the stored key",
                "the user's DPAPI master-key chain is unavailable, e.g. after a Windows password " +
                    "reset or copying the profile to another machine",
                e,
            )
        }
    }

    override fun put(alias: String, keyBytes: ByteArray) {
        val wrapped = Crypt32Util.cryptProtectData(keyBytes)
        store.putString(alias, encodeBase64(wrapped))
    }

    override fun delete(alias: String) = store.remove(alias)

    private companion object {
        const val BLOB_PREFIX = "ksafe_dpapi_"
    }
}
