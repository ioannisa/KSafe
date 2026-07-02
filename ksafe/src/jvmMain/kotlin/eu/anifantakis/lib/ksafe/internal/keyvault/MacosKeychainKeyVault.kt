package eu.anifantakis.lib.ksafe.internal.keyvault

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference

/**
 * Whether a `SecKeychainAddGenericPassword` OSStatus means the key write FAILED and must
 * throw (fail closed). `errSecDuplicateItem` (-25299) IS a failure here (FEEDBACK_4 low):
 * [MacosKeychainKeyVault.put] is a delete-then-add upsert, so a duplicate error means the
 * preceding delete did NOT remove the existing item — the NEW key was never stored and the
 * stale one remains. Swallowing it would report success while silently losing the write,
 * making everything re-encrypted under the intended key undecryptable. Only `errSecSuccess`
 * (0) is a success. Pure so it's unit-testable without a live Keychain.
 */
internal fun macosKeychainAddIsFailure(status: Int): Boolean = status != 0 // errSecSuccess

/**
 * macOS key vault backed by the **login Keychain** via JNA bindings to
 * `Security.framework`.
 *
 * It uses the classic `SecKeychainAddGenericPassword` / `…Find…` /
 * `SecKeychainItemDelete` generic-password API. That API is deprecated by
 * Apple in favour of the `SecItem*` data-protection API but remains fully
 * functional on current macOS and is dramatically simpler to bind from the JVM
 * (plain C strings + byte buffers vs. constructing CoreFoundation
 * dictionaries). This matches the chosen scope: *standard login/data-protection
 * Keychain, not Secure Enclave* — a JVM process cannot reuse KSafe's
 * Kotlin/Native Secure Enclave path anyway.
 *
 * The Keychain itself stores the secret (no separate file persistence). On
 * Macs with a Secure Enclave (Apple Silicon / T2) the login keychain's key
 * hierarchy is SEP-gated; on older Intel Macs it is login-password-derived.
 * Either way this is a large improvement over a plaintext key file: the blob
 * is not readable from disk without the user's login session.
 */
internal class MacosKeychainKeyVault(
    /**
     * App-isolation namespace. The login Keychain is per-OS-user and shared
     * by every process, so the generic-password **service** is namespaced
     * (`eu.anifantakis.ksafe.<ns>`) to keep different desktop apps' keys
     * apart. Blank = the historical un-namespaced service. The account stays
     * the bare alias, so the legacy DataStore migration source is unaffected.
     */
    appNamespace: String = "",
) : JvmKeyVault {

    override val name: String = "macOS Keychain (Security.framework, login keychain)"
    override val isOsBacked: Boolean = true

    private val service =
        (if (appNamespace.isBlank()) SERVICE_NAME else "$SERVICE_NAME.$appNamespace")
            .toByteArray(Charsets.UTF_8)

    override fun get(alias: String): ByteArray? {
        val account = alias.toByteArray(Charsets.UTF_8)
        val pwdLen = IntByReference()
        val pwdData = PointerByReference()
        val status = SEC.SecKeychainFindGenericPassword(
            null,
            service.size, service,
            account.size, account,
            pwdLen, pwdData,
            null,
        )
        // Genuinely absent → null (a true miss the orphan sweep / migration may act on).
        if (status == ERR_SEC_ITEM_NOT_FOUND) return null
        // Any other non-success status means the lookup itself failed, NOT that the
        // key is absent — e.g. errSecInteractionNotAllowed when the login keychain is
        // locked (SSH session, FileVault edge cases). Throw the "key vault unavailable"
        // contract so encrypted reads fall back to defaults, the orphan sweep leaves
        // the still-recoverable ciphertext intact, and writes fail closed rather than
        // minting a divergent key.
        if (status != ERR_SEC_SUCCESS) {
            throw IllegalStateException(
                "KSafe: key vault unavailable — macOS Keychain lookup failed for alias " +
                    "\"$alias\" (OSStatus $status; the login keychain may be locked or " +
                    "inaccessible).",
                KeychainException("SecKeychainFindGenericPassword", status),
            )
        }
        val ptr = pwdData.value ?: return null
        return try {
            if (pwdLen.value <= 0) null else ptr.getByteArray(0, pwdLen.value)
        } finally {
            SEC.SecKeychainItemFreeContent(null, pwdData.value)
        }
    }

    override fun put(alias: String, keyBytes: ByteArray) {
        // Delete-then-add: simplest correct upsert (avoids building a
        // SecKeychainAttributeList for SecKeychainItemModifyContent).
        delete(alias)
        val account = alias.toByteArray(Charsets.UTF_8)
        val status = SEC.SecKeychainAddGenericPassword(
            null,
            service.size, service,
            account.size, account,
            keyBytes.size, keyBytes,
            null,
        )
        // errSecDuplicateItem is NOT tolerated (FEEDBACK_4 low): it means the delete above
        // failed to remove the existing item, so this add did NOT replace the key — the
        // stale one is still there. Fail closed so the write isn't silently lost.
        if (macosKeychainAddIsFailure(status)) {
            throw KeychainException("SecKeychainAddGenericPassword", status)
        }
    }

    override fun delete(alias: String) {
        val account = alias.toByteArray(Charsets.UTF_8)
        val itemRef = PointerByReference()
        val status = SEC.SecKeychainFindGenericPassword(
            null,
            service.size, service,
            account.size, account,
            null, null,
            itemRef,
        )
        if (status == ERR_SEC_ITEM_NOT_FOUND || status != ERR_SEC_SUCCESS) return
        itemRef.value?.let { SEC.SecKeychainItemDelete(it) }
    }

    /** JNA mapping of the subset of Security.framework we need. */
    private interface SecurityLibrary : Library {
        fun SecKeychainAddGenericPassword(
            keychain: Pointer?,
            serviceNameLength: Int, serviceName: ByteArray,
            accountNameLength: Int, accountName: ByteArray,
            passwordLength: Int, passwordData: ByteArray,
            itemRef: PointerByReference?,
        ): Int

        fun SecKeychainFindGenericPassword(
            keychainOrArray: Pointer?,
            serviceNameLength: Int, serviceName: ByteArray,
            accountNameLength: Int, accountName: ByteArray,
            passwordLength: IntByReference?, passwordData: PointerByReference?,
            itemRef: PointerByReference?,
        ): Int

        fun SecKeychainItemDelete(itemRef: Pointer): Int

        fun SecKeychainItemFreeContent(attrList: Pointer?, data: Pointer?): Int
    }

    private class KeychainException(call: String, status: Int) :
        RuntimeException("KSafe macOS Keychain: $call failed (OSStatus=$status)")

    private companion object {
        const val SERVICE_NAME = "eu.anifantakis.ksafe"

        // <Security/SecBase.h>
        const val ERR_SEC_SUCCESS = 0
        const val ERR_SEC_DUPLICATE_ITEM = -25299
        const val ERR_SEC_ITEM_NOT_FOUND = -25300

        val SEC: SecurityLibrary = Native.load("Security", SecurityLibrary::class.java)
    }
}
