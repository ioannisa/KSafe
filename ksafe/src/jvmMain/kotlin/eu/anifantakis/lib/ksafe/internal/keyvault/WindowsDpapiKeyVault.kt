package eu.anifantakis.lib.ksafe.internal.keyvault

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import com.sun.jna.platform.win32.Crypt32Util
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Windows key vault using **DPAPI** (`CryptProtectData` / `CryptUnprotectData`)
 * via JNA's `jna-platform` [Crypt32Util].
 *
 * DPAPI only *wraps* data — it does not store it. The key is therefore:
 * 1. Encrypted with a key derived from the current user's Windows login
 *    credentials (current-user scope, the [Crypt32Util] default).
 * 2. The resulting opaque blob is Base64-encoded and persisted in the
 *    DataStore file under the `ksafe_dpapi_` prefix.
 *
 * Storing the wrapped blob in a file is safe: it is cryptographically useless
 * to anyone who is not logged in as this Windows user. This defeats offline
 * disk theft, backups and other-user access — the things the legacy
 * plaintext-in-file scheme did not.
 *
 * It does **not** defend against code running as the same user while logged in
 * (DPAPI will transparently unprotect for any such process) — that requires the
 * opt-in passphrase mode, out of scope here.
 */
internal class WindowsDpapiKeyVault(
    dataStore: DataStore<Preferences>,
    /**
     * App-isolation namespace folded into the wrapped-blob key prefix
     * (`ksafe_dpapi_<ns>_`) so different apps sharing a DataStore directory
     * don't collide. Blank = the historical un-namespaced prefix. This is the
     * DPAPI *destination*, not the frozen legacy `ksafe_key_` migration
     * source, so namespacing it is migration-safe.
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
        // Genuinely absent: no stored blob → null (so the orphan sweep / migration
        // treat it as a true miss).
        val wrapped = store.getString(alias) ?: return null
        // A stored blob that can no longer be unprotected is NOT a miss: the user's
        // DPAPI master-key chain is unavailable (admin-forced Windows password reset,
        // or the profile/blob copied to another machine). Map it to the "key vault
        // unavailable" contract — the same wording Linux uses — so KSafeCore treats it
        // as non-transient AND non-orphan: encrypted reads return their defaults and
        // the orphan sweep leaves the still-recoverable ciphertext intact, instead of a
        // raw Win32Exception that only incidentally avoids misclassification. Writes
        // fail closed rather than minting a divergent key. See deep-review #57.
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
