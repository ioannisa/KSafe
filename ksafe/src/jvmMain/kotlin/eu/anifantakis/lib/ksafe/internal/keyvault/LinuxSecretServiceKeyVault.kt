package eu.anifantakis.lib.ksafe.internal.keyvault

import eu.anifantakis.lib.ksafe.encodeBase64
import eu.anifantakis.lib.ksafe.decodeBase64
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.ptr.PointerByReference
import eu.anifantakis.lib.ksafe.internal.KSAFE_OS_STORE_IDENTITY

/**
 * Linux key vault backed by the freedesktop Secret Service (`libsecret` through JNA); keys live
 * in the login keyring, Base64-encoded because the libsecret password APIs take C strings.
 */
internal class LinuxSecretServiceKeyVault(
    // Folded into the lookup attribute as `<ns>/<alias>`; the collection is per-OS-user, so two
    // apps must not collide on one alias. Blank = the historical un-namespaced value.
    private val appNamespace: String = "",
) : JvmKeyVault {

    override val name: String = "Linux Secret Service (libsecret, login keyring)"
    override val isOsBacked: Boolean = true

    private fun nsAlias(alias: String): String =
        if (appNamespace.isBlank()) alias else "$appNamespace/$alias"

    override fun get(alias: String): ByteArray? {
        // libsecret returns NULL for both a miss and a failed lookup; GError** disambiguates.
        val errorRef = PointerByReference()
        val ptr: Pointer? = SECRET.secret_password_lookup_sync(
            schema(), null, errorRef,
            ATTR_ALIAS, nsAlias(alias), null,
        )
        errorRef.value?.let { gerror ->
            // "Vault unavailable", not "key absent", or the orphan sweep deletes live ciphertext.
            runCatching { GLIB?.g_error_free(gerror) }
            throw vaultUnavailable(
                alias,
                "Linux Secret Service lookup failed",
                "login keyring locked or unreachable",
            )
        }
        ptr ?: return null
        return try {
            val b64 = ptr.getString(0)
            if (b64.isNullOrEmpty()) null else decodeBase64(b64)
        } finally {
            SECRET.secret_password_free(ptr)
        }
    }

    override fun put(alias: String, keyBytes: ByteArray) {
        val ok = SECRET.secret_password_store_sync(
            schema(),
            null, // null collection => default login keyring
            "KSafe encryption key ($alias)",
            encodeBase64(keyBytes),
            null, null,
            ATTR_ALIAS, nsAlias(alias), null,
        )
        if (ok == 0) {
            throw RuntimeException("KSafe Linux Secret Service: secret_password_store_sync failed")
        }
    }

    override fun delete(alias: String) {
        runCatching {
            SECRET.secret_password_clear_sync(schema(), null, null, ATTR_ALIAS, nsAlias(alias), null)
        }
    }

    // A fresh struct per call: it is native memory, and one shared across threads races on write().
    private fun schema(): SecretSchema {
        val s = SecretSchema()
        s.name = SCHEMA_NAME
        s.flags = SECRET_SCHEMA_NONE
        s.attributes[0].name = ATTR_ALIAS
        s.attributes[0].type = SECRET_SCHEMA_ATTRIBUTE_STRING
        // attrs[1].name stays NULL => libsecret treats it as the terminator.
        s.write()
        return s
    }

    /** Mirrors the layout of `SecretSchema` from `<libsecret/secret-schema.h>`: 32 inline
     *  attribute slots, then the reserved tail. Any drift misreads the struct natively. */
    @Structure.FieldOrder(
        "name", "flags", "attributes",
        "reserved", "reserved1", "reserved2", "reserved3",
        "reserved4", "reserved5", "reserved6", "reserved7",
    )
    class SecretSchema : Structure() {
        @JvmField var name: String? = null
        @JvmField var flags: Int = 0

        @JvmField
        var attributes: Array<Attribute> =
            @Suppress("UNCHECKED_CAST")
            (Attribute().toArray(32) as Array<Attribute>)

        @JvmField var reserved: Int = 0
        @JvmField var reserved1: Pointer? = null
        @JvmField var reserved2: Pointer? = null
        @JvmField var reserved3: Pointer? = null
        @JvmField var reserved4: Pointer? = null
        @JvmField var reserved5: Pointer? = null
        @JvmField var reserved6: Pointer? = null
        @JvmField var reserved7: Pointer? = null

        @Structure.FieldOrder("name", "type")
        class Attribute : Structure() {
            @JvmField var name: String? = null
            @JvmField var type: Int = 0
        }
    }

    /** JNA mapping of libsecret; the varargs are attribute name/value pairs terminated by NULL. */
    private interface SecretLibrary : Library {
        fun secret_password_lookup_sync(
            schema: SecretSchema,
            cancellable: Pointer?,
            // GError** out-param: set on failure, NULL on success/not-found.
            error: PointerByReference?,
            vararg attributes: Any?,
        ): Pointer?

        fun secret_password_store_sync(
            schema: SecretSchema,
            collection: String?,
            label: String,
            password: String,
            cancellable: Pointer?,
            error: Pointer?,
            vararg attributes: Any?,
        ): Int

        fun secret_password_clear_sync(
            schema: SecretSchema,
            cancellable: Pointer?,
            error: Pointer?,
            vararg attributes: Any?,
        ): Int

        fun secret_password_free(password: Pointer?)
    }

    private interface GLibLibrary : Library {
        fun g_error_free(error: Pointer)
    }

    private companion object {
        const val SCHEMA_NAME = KSAFE_OS_STORE_IDENTITY
        const val ATTR_ALIAS = "alias"

        // <libsecret/secret-schema.h>
        const val SECRET_SCHEMA_NONE = 0
        const val SECRET_SCHEMA_ATTRIBUTE_STRING = 0

        val SECRET: SecretLibrary = Native.load("secret-1", SecretLibrary::class.java)

        // Nullable: a missing soname must not break the throw-on-keyring-error path.
        val GLIB: GLibLibrary? =
            runCatching { Native.load("glib-2.0", GLibLibrary::class.java) }.getOrNull()
    }
}
