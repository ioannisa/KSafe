package eu.anifantakis.lib.ksafe.internal.keyvault

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Linux key vault backed by the **Secret Service** (the freedesktop.org
 * D-Bus secrets API — GNOME Keyring, KWallet's secrets bridge, KeePassXC, …)
 * via JNA bindings to `libsecret`.
 *
 * Keys are stored in the user's default login keyring under schema
 * `eu.anifantakis.ksafe`, keyed by an `alias` attribute. The keyring daemon
 * holds the secret; on disk it is encrypted with a key derived from the user's
 * login password (and unlocked at session login). This is a large improvement
 * over a plaintext key file: an attacker with the disk but not the live
 * session / login password cannot recover keys.
 *
 * Availability is not guaranteed on Linux — headless servers frequently have
 * no `libsecret` and no running keyring. [JvmKeyVaultProvider] self-tests this
 * vault and falls back to the plaintext store (with a warning) when libsecret
 * is missing or no Secret Service is reachable, so construction here only fails
 * loudly if the library cannot even be loaded.
 *
 * Binary key bytes are Base64-encoded before storage because the libsecret
 * password APIs take NUL-terminated C strings.
 */
internal class LinuxSecretServiceKeyVault : JvmKeyVault {

    override val name: String = "Linux Secret Service (libsecret, login keyring)"
    override val isOsBacked: Boolean = true

    @OptIn(ExperimentalEncodingApi::class)
    override fun get(alias: String): ByteArray? {
        val ptr: Pointer? = SECRET.secret_password_lookup_sync(
            schema(), null, null,
            ATTR_ALIAS, alias, null,
        )
        ptr ?: return null
        return try {
            val b64 = ptr.getString(0)
            if (b64.isNullOrEmpty()) null else Base64.decode(b64)
        } finally {
            SECRET.secret_password_free(ptr)
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun put(alias: String, keyBytes: ByteArray) {
        val ok = SECRET.secret_password_store_sync(
            schema(),
            null, // null collection => default login keyring
            "KSafe encryption key ($alias)",
            Base64.encode(keyBytes),
            null, null,
            ATTR_ALIAS, alias, null,
        )
        if (ok == 0) {
            throw RuntimeException("KSafe Linux Secret Service: secret_password_store_sync failed")
        }
    }

    override fun delete(alias: String) {
        // Best-effort; ignore result (FALSE simply means "nothing to clear").
        runCatching {
            SECRET.secret_password_clear_sync(schema(), null, null, ATTR_ALIAS, alias, null)
        }
    }

    // A fresh SecretSchema per call: cheap, avoids any shared-mutable-native
    // state, and keeps the (rare) key operations trivially thread-safe.
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

    /**
     * Mirrors the public layout of `SecretSchema` from `<libsecret/secret-schema.h>`
     * (32 inline attribute slots + 8 reserved trailing fields).
     */
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

    /** JNA mapping of the subset of libsecret we use (varargs = attr pairs + NULL). */
    private interface SecretLibrary : Library {
        fun secret_password_lookup_sync(
            schema: SecretSchema,
            cancellable: Pointer?,
            error: Pointer?,
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

    private companion object {
        const val SCHEMA_NAME = "eu.anifantakis.ksafe"
        const val ATTR_ALIAS = "alias"

        // <libsecret/secret-schema.h>
        const val SECRET_SCHEMA_NONE = 0
        const val SECRET_SCHEMA_ATTRIBUTE_STRING = 0

        val SECRET: SecretLibrary = Native.load("secret-1", SecretLibrary::class.java)
    }
}
