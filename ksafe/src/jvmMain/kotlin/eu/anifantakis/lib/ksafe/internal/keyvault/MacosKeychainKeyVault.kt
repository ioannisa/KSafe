package eu.anifantakis.lib.ksafe.internal.keyvault

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference

/**
 * Whether a `SecKeychainAddGenericPassword` OSStatus means the write FAILED and must throw
 * (fail closed); only `errSecSuccess` (0) is a success. `errSecDuplicateItem` (-25299) counts
 * as failure: [MacosKeychainKeyVault.put] is a delete-then-add upsert, so a duplicate means
 * the delete didn't remove the old item and the new key was never stored — swallowing it
 * would report success while silently losing the write. Pure, so unit-testable without a
 * live Keychain.
 */
internal fun macosKeychainAddIsFailure(status: Int): Boolean = status != 0 // errSecSuccess

/**
 * macOS key vault backed by the **login Keychain** via JNA bindings to
 * `Security.framework`, using the classic `SecKeychainAddGenericPassword` /
 * `…Find…` / `…ItemDelete` generic-password API — deprecated in favour of the
 * `SecItem*` API but far simpler to bind (C strings vs. CoreFoundation dicts)
 * and fully functional. Scope is the standard login Keychain, not Secure Enclave
 * (a JVM process can't reuse KSafe's Kotlin/Native SE path).
 *
 * The Keychain stores the secret (no separate file). The blob is not readable
 * from disk without the user's login session — a large improvement over a
 * plaintext key file.
 */
internal class MacosKeychainKeyVault(
    /**
     * App-isolation namespace. The login Keychain is per-OS-user, so the
     * generic-password **service** is namespaced (`eu.anifantakis.ksafe.<ns>`)
     * to keep different apps' keys apart. Blank = the historical un-namespaced
     * service. The account stays the bare alias.
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
        // Any other non-success means the lookup FAILED, not that the key is absent (e.g.
        // errSecInteractionNotAllowed on a locked keychain). Throw the "key vault unavailable"
        // contract so reads fall back to defaults, the orphan sweep leaves the recoverable
        // ciphertext intact, and writes fail closed instead of minting a divergent key.
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
        // Delete-then-add: simplest correct upsert.
        delete(alias)
        val account = alias.toByteArray(Charsets.UTF_8)
        val status = SEC.SecKeychainAddGenericPassword(
            null,
            service.size, service,
            account.size, account,
            keyBytes.size, keyBytes,
            null,
        )
        // Fail closed (see macosKeychainAddIsFailure): an errSecDuplicateItem here means the
        // delete didn't remove the old item, so the write was silently lost.
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
