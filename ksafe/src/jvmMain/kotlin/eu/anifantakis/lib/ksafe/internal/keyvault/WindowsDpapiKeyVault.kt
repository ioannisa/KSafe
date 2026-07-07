package eu.anifantakis.lib.ksafe.internal.keyvault

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import com.sun.jna.platform.win32.Crypt32Util
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Windows key vault using **DPAPI** (`CryptProtectData` / `CryptUnprotectData`)
 * via JNA's `jna-platform` [Crypt32Util]. DPAPI only *wraps* data: the key is
 * encrypted under the current user's login credentials, then the opaque blob is
 * Base64-encoded and persisted in the DataStore file under `ksafe_dpapi_`.
 *
 * Storing the wrapped blob is safe — it's useless to anyone not logged in as
 * this Windows user, defeating offline disk theft and other-user access. It does
 * NOT defend against code running as the same logged-in user (DPAPI unprotects
 * transparently); that needs the opt-in passphrase mode, out of scope here.
 */
internal class WindowsDpapiKeyVault(
    dataStore: DataStore<Preferences>,
    /**
     * App-isolation namespace folded into the wrapped-blob key prefix
     * (`ksafe_dpapi_<ns>_`) so apps sharing a DataStore directory don't collide.
     * Blank = the historical un-namespaced prefix.
     */
    appNamespace: String = "",
) : JvmKeyVault {

    private val store = DataStorePrefStore(
        dataStore,
        if (appNamespace.isBlank()) BLOB_PREFIX else "$BLOB_PREFIX${appNamespace}_",
    )

    override val name: String = "Windows DPAPI (CryptProtectData, current-user)"
    override val isOsBacked: Boolean = true

    @OptIn(ExperimentalEncodingApi::class)
    override fun get(alias: String): ByteArray? {
        // No stored blob = genuine miss (null), safe for the orphan sweep / migration.
        val wrapped = store.getString(alias) ?: return null
        // A blob that can no longer be unprotected (password reset, profile copied to
        // another machine) is NOT a miss — throw the "key vault unavailable" contract so
        // reads fall back to defaults, the orphan sweep leaves the recoverable ciphertext
        // intact, and writes fail closed instead of minting a divergent key.
        return try {
            Crypt32Util.cryptUnprotectData(Base64.decode(wrapped))
        } catch (e: Throwable) {
            throw IllegalStateException(
                "KSafe: key vault unavailable — Windows DPAPI could not unprotect the stored " +
                    "key for alias \"$alias\" (the user's DPAPI master-key chain is unavailable, " +
                    "e.g. after a Windows password reset or copying the profile to another machine).",
                e,
            )
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun put(alias: String, keyBytes: ByteArray) {
        val wrapped = Crypt32Util.cryptProtectData(keyBytes)
        store.putString(alias, Base64.encode(wrapped))
    }

    override fun delete(alias: String) = store.remove(alias)

    private companion object {
        const val BLOB_PREFIX = "ksafe_dpapi_"
    }
}
