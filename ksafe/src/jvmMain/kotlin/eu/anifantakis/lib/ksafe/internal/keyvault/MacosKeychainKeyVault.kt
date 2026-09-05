package eu.anifantakis.lib.ksafe.internal.keyvault

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference
import eu.anifantakis.lib.ksafe.internal.KSAFE_OS_STORE_IDENTITY

// Fail closed: `put` is a delete-then-add upsert, so even errSecDuplicateItem means the delete
// failed and the new key was never stored — swallowing it would report a lost write as success.
internal fun macosKeychainAddIsFailure(status: Int): Boolean = status != 0

// Login Keychain via JNA, not the Secure Enclave. The deprecated generic-password API binds far
// more simply than SecItem* (C strings vs CoreFoundation dicts).
internal class MacosKeychainKeyVault(
    // Service becomes eu.anifantakis.ksafe.<ns>; blank keeps the historical un-namespaced service.
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
        if (status == ERR_SEC_ITEM_NOT_FOUND) return null
        // Any other non-success is a lookup failure, not an absent key: throwing keeps the orphan
        // sweep off recoverable ciphertext and stops writes minting a divergent key.
        if (status != ERR_SEC_SUCCESS) {
            throw vaultUnavailable(
                alias,
                "macOS Keychain lookup failed",
                "OSStatus $status; the login keychain may be locked or inaccessible",
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
        delete(alias)
        val account = alias.toByteArray(Charsets.UTF_8)
        val status = SEC.SecKeychainAddGenericPassword(
            null,
            service.size, service,
            account.size, account,
            keyBytes.size, keyBytes,
            null,
        )
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
        // Best-effort: if the old item survives, put()'s add fails and reports it.
        if (status == ERR_SEC_ITEM_NOT_FOUND || status != ERR_SEC_SUCCESS) return
        val ref = itemRef.value ?: return
        try {
            SEC.SecKeychainItemDelete(ref)
        } finally {
            // Find returns a +1 CFTypeRef and ItemDelete does not release it, so without CFRelease
            // every delete leaks a native ref for the process lifetime.
            CF.CFRelease(ref)
        }
    }

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

    private interface CoreFoundationLibrary : Library {
        fun CFRelease(cf: Pointer)
    }

    private class KeychainException(call: String, status: Int) :
        RuntimeException("KSafe macOS Keychain: $call failed (OSStatus=$status)")

    private companion object {
        const val SERVICE_NAME = KSAFE_OS_STORE_IDENTITY

        // <Security/SecBase.h>
        const val ERR_SEC_SUCCESS = 0
        const val ERR_SEC_DUPLICATE_ITEM = -25299
        const val ERR_SEC_ITEM_NOT_FOUND = -25300

        val SEC: SecurityLibrary = Native.load("Security", SecurityLibrary::class.java)
        val CF: CoreFoundationLibrary = Native.load("CoreFoundation", CoreFoundationLibrary::class.java)
    }
}
